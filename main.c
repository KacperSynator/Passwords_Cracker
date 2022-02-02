#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <stdbool.h>

/* Program description:
 * Program is performing dictionary attack on given hashed passwords. It creates 8 threads in total, first thread (consumer)
 * receives cracked passwords from cracking threads and then prints it, this thread is communicating with other threads
 * by conditional value. Other threads generate passwords using given or default dictionary, every thread is generating
 * passwords using different method. Three basic cracking threads create passwords from different latter cases and adds
 * numbers before or/and after generated word. Another three threads generate two word passwords separated by " ", "2", "4"
 * or nothing, words are modified same as in basic threads. The last thread generates numeric passwords. Main loop is 
 * reading user input. Program may be reset by typing a path to new passwords file. Program prints statistics after typing
 * "stats" or sending a SIGHUP signal also prints on program exit and passwords file reset. User may exit the program 
 * typing "exit" (safest) or by sending SIGINT (CTRL + C) but main hangs on reading input so something must be typed to
 * break main loop. Main in the end is performing a cleaning especially memory freeing. 
 */

/*
 * dictionaries: https://web.archive.org/web/20120207113205/http://www.insidepro.com/eng/download.shtml
 * -> InsidePro (Mini) -> very good (1.9 MB) 140k passwords
 * -> Facebook (Words) -> better but heavy (19 MB) 2M passwords
 * openssl library: sudo apt-get install openssl-dev
 * compile flags: -lssl -lcrypto -pthread
 */

#define USAGE "usage: ./pass_cr passwords_file [dictionary_file]\n"
#define DEFAULT_DICTIONARY "inside_pro_mini.dic"
#define BUF_SIZE 64
#define NUM_THREADS 8
#define U_LONG_MAX 4294967295

/* mutex for thread count (thread id), conditional value and associated mutex for consumer cracking threads communication,
 * read write lock for threads reset after reading a new password file */
pthread_mutex_t count_mutex;
pthread_mutex_t cond_mutex;
pthread_cond_t pass_cracked_cv;
pthread_rwlock_t tsd_rwlock;

/* global flags */
static volatile bool running = true;
static volatile bool show_stats = false;
static volatile bool reset = false;

/* structure containing all necessary data for threads, created in main and passed as an argument to all threads */
struct thread_shared_data{
    char** dict_ptr;
    char** pass_ptr;
    char** br_pass_ptr;
    bool* is_cracked_ptr;
    unsigned long dict_size;
    unsigned long pass_size;
    unsigned long br_pass_size;
    unsigned int basic_thread_count;
    unsigned int two_word_thread_count;
};

/* function that exits application, also handler for SIGINT (CTRL + C) */
void quit_program()
{
    printf("\nQuiting\n");
    running = false;
    show_stats = true;
    pthread_cond_broadcast(&pass_cracked_cv);
}

/* function that makes consumer thread print statistics, also handler for SIGHUP */
void print_statistics()
{
    show_stats = true;
    pthread_mutex_lock(&cond_mutex);
    pthread_cond_broadcast(&pass_cracked_cv);
    pthread_mutex_unlock(&cond_mutex);
}

/* function that makes a hash of a given string using MD5 algorithm */
void md5_hash(char * in_str, char ** out_str)
{
    if(*out_str != NULL) free(*out_str);
    *out_str = (char *)malloc(33*sizeof(char));

    unsigned char digest[16];
    MD5_CTX ctx;
    MD5_Init(&ctx);

    MD5_Update(&ctx, in_str, strlen(in_str));
    MD5_Final(digest, &ctx);

    for(int n = 0; n < 16; ++n)
        sprintf(&(*out_str)[n*2],"%02x", (unsigned int)digest[n]);
}

/* thread that waits for broken passwords, when password is received thread prints password, this thread also
 * prints statistics that are reset after loading new passwords  */
void *consumer_thread(void *arg)
{
    struct thread_shared_data* my_tsd;
    my_tsd = (struct thread_shared_data*) arg;

    while(running)
    {
        pthread_mutex_lock(&cond_mutex);
        pthread_cond_wait(&pass_cracked_cv, &cond_mutex);
        if(!show_stats)
        {
            /* print cracked password */
            if(my_tsd->br_pass_size > 0)
                printf("consumer thread: cracked password received: %s\n", my_tsd->br_pass_ptr[my_tsd->br_pass_size - 1]);
        }
        else if(show_stats)
        {
            /* print statistics */
            printf("consumer thread: stats -> cracked %lu of %lu  %.2f%%\n",my_tsd->br_pass_size,
                   my_tsd->pass_size, ((double) my_tsd->br_pass_size / (double) my_tsd->pass_size * 100));
            show_stats = false;
        }
        pthread_mutex_unlock(&cond_mutex);
    }
    printf("consumer thread: exit\n");
    pthread_exit(NULL);
}

/* function that checks if generated passwords is the same as loaded */
void check_passwords(char * created_pass, struct thread_shared_data * my_tsd, unsigned int id)
{
    char * hashed_pass = NULL;
    md5_hash(created_pass, &hashed_pass);
    for(unsigned long j = 0; j < my_tsd->pass_size && running; j++)
    {
        if(my_tsd->is_cracked_ptr[j] == true) continue; // skip already broken password
        if(!strcmp(my_tsd->pass_ptr[j], hashed_pass))
        {
            /* password broken */
            pthread_mutex_lock(&cond_mutex);
            printf("cracking thread %u: password broken -> %s\n", id, created_pass);

            my_tsd->is_cracked_ptr[j] = true;
            my_tsd->br_pass_ptr = realloc(my_tsd->br_pass_ptr, (++my_tsd->br_pass_size)*sizeof(char *));
            my_tsd->br_pass_ptr[my_tsd->br_pass_size - 1] = (char*)malloc((strlen(created_pass)+1)*sizeof(char));
            strcpy(my_tsd->br_pass_ptr[my_tsd->br_pass_size - 1], created_pass);

            pthread_cond_signal(&pass_cracked_cv);
            pthread_mutex_unlock(&cond_mutex);
        }
    }
    free(hashed_pass);
}

/* function that changes all string uppercase letters to lowercase letters */
void to_lowercase(char ** str)
{
    for(int i=0; i < strlen(*str); i++)
        if((*str)[i] <= 'Z' && (*str)[i] >= 'A' )
            (*str)[i] += 32;
}

/* function that changes all string lowercase letters to uppercase letters */
void to_uppercase(char ** str)
{
    for(int i=0; i < strlen(*str); i++)
        if((*str)[i] <= 'z' && (*str)[i] >= 'a' )
            (*str)[i] -= 32;
}

/* function change string depending on thread id
 * id == 0 -> all lowercase
 * id == 1 -> first uppercase
 * id == 2 -> all uppercase
 */
void change_string_by_id(unsigned int id, char ** str)
{
    switch (id)
    {
        case 0: // all lowercase
        {
            to_lowercase(str);
            break;
        }
        case 1: // first letter uppercase
        {
            to_lowercase(str);
            unsigned int i=0;
            while((*str)[i] > 'z' || (*str)[i] < 'a') i++;
            (*str)[i] -= 32;
            break;
        }
        case 2: // all uppercase
        {
            to_uppercase(str);
            break;
        }
    }
}

/* function resets cracking threads depending on thread id
 * arguments: thread id and pointers to all values that needs to be reset
 * if thread doesnt have one of those values use NULL
 */
void reset_thread(unsigned int id, unsigned long * num, bool * first_loop, unsigned long * i)
{
    printf("cracking thread %d: reset\n", id);
    if(id >= 0 && id <= 2) // cracking_thread_basic
    {
        *num = 0;
        *first_loop = true;
    }
    else if(id == 3) // cracking_thread_numbers
    {
        *num = 0;
    }
    else if(id >= 4 && id <= 6) // cracking_thread_two_words
    {
        *i = 0;
    }
    while(reset) sleep(1);
    printf("cracking thread %d: start\n", id);
}

/* thread that cracks passwords, thread adds numbers before or/and after every word (except first loop),
 * words from dictionary are modified depending on thread id
 * id == 0 -> all lowercase
 * id == 1 -> first uppercase
 * id == 2 -> all uppercase
 */
void *cracking_thread_basic(void *arg)
{
    struct thread_shared_data* my_tsd;
    my_tsd = (struct thread_shared_data*) arg;

    pthread_mutex_lock(&count_mutex);
    unsigned int id = my_tsd->basic_thread_count;
    my_tsd->basic_thread_count++;
    pthread_mutex_unlock(&count_mutex);

    char * created_pass = NULL;
    unsigned long num = 0;
    bool first_loop = true;
    char num_buf[11]; // unsigned long range [0, 4294967295] -> 10 chars + '/0'
    while(running)
    {
        if(first_loop)
        {
            first_loop = false;
            for(unsigned long i = 0; i < my_tsd->dict_size && running; i++)
            {
                created_pass = (char *) malloc((strlen(my_tsd->dict_ptr[i]) + 1) * sizeof(char));
                strcpy(created_pass, my_tsd->dict_ptr[i]);
                change_string_by_id(id, &created_pass);
                if(reset)
                {
                    reset_thread(id, &num, &first_loop, NULL);
                    free(created_pass);
                    break;
                }
                pthread_rwlock_rdlock(&tsd_rwlock);
                check_passwords(created_pass, my_tsd, id);
                pthread_rwlock_unlock(&tsd_rwlock);
                free(created_pass);
            }
        }
        else
        {
            for(unsigned long i = 0; i < my_tsd->dict_size && running; i++)
            {
                if(reset)
                {
                    reset_thread(id, &num, &first_loop, NULL);
                    free(created_pass);
                    break;
                }
                sprintf(num_buf, "%lu", num);
                created_pass = (char *)malloc((strlen(my_tsd->dict_ptr[i])+strlen(num_buf)+1)*sizeof(char));
                /* dictionary word number */
                strcat(created_pass, my_tsd->dict_ptr[i]);
                strcat(created_pass, num_buf);
                change_string_by_id(id, &created_pass);
                pthread_rwlock_rdlock(&tsd_rwlock);
                check_passwords(created_pass, my_tsd, id);
                pthread_rwlock_unlock(&tsd_rwlock);
                /* clear buffer */
                sprintf(created_pass, "");
                /* number dictionary word */
                strcat(created_pass, num_buf);
                strcat(created_pass, my_tsd->dict_ptr[i]);
                change_string_by_id(id, &created_pass);

                pthread_rwlock_rdlock(&tsd_rwlock);
                check_passwords(created_pass, my_tsd, id);
                pthread_rwlock_unlock(&tsd_rwlock);
                /* number dictionary word number */ // not effective (zero passwords cracked)
                /*created_pass = (char *)realloc(created_pass ,(strlen(my_tsd->dict_ptr[i])+2*strlen(num_buf)+1)*sizeof(char));
                strcat(created_pass, num_buf);
                change_string_by_id(id, &created_pass);
                pthread_rwlock_rdlock(&tsd_rwlock);
                check_passwords(created_pass, my_tsd, id);
                pthread_rwlock_unlock(&tsd_rwlock);
                free(created_pass);*/
            }
            if(num == U_LONG_MAX) num = 0;
            else num++;
        }
    }
    printf("cracking thread %u: exit\n", id);
    pthread_exit(NULL);
}

/* thread that cracks 2 word passwords, words are separated by space or 2 or 4 or nothing
 * words from dictionary are modified depending on thread id
 * id == 0 -> all lowercase
 * id == 1 -> first uppercase
 * id == 2 -> all uppercase
 */ // not effective (zero passwords cracked)
void *cracking_thread_two_words(void *arg)
{
    struct thread_shared_data* my_tsd;
    my_tsd = (struct thread_shared_data*) arg;

    pthread_mutex_lock(&count_mutex);
    unsigned int local_id = my_tsd->two_word_thread_count;
    my_tsd->two_word_thread_count++;
    pthread_mutex_unlock(&count_mutex);
    unsigned int global_id = local_id + 4;

    char * created_pass = NULL;
    char * first_word = NULL;
    char * second_word = NULL;
    char separators[6] = " 24";
    while(running)
    {
        for(unsigned long i = 0; i < my_tsd->dict_size && running; i++)
        {
            unsigned long first_size = strlen(my_tsd->dict_ptr[i]);
            first_word = (char *)malloc(first_size*sizeof(char)+1);
            strcpy(first_word, my_tsd->dict_ptr[i]);
            for(unsigned long j = i; j < my_tsd->dict_size && running; j++)
            {
                if(reset)
                {
                    reset_thread(global_id, NULL, NULL, &i);
                    break;
                }
                unsigned long second_size = strlen(my_tsd->dict_ptr[j]);
                second_word = (char *)malloc(second_size*sizeof(char)+1);
                strcpy(second_word, my_tsd->dict_ptr[j]);
                created_pass = (char *)malloc((first_size + second_size + 2)*sizeof(char));
                /* no separator */
                /* first_word second_word */
                change_string_by_id(local_id, &first_word);
                change_string_by_id(local_id, &second_word);
                strcat(created_pass, first_word);
                strcat(created_pass, second_word);
                pthread_rwlock_rdlock(&tsd_rwlock);
                check_passwords(created_pass, my_tsd, global_id);
                pthread_rwlock_unlock(&tsd_rwlock);
                /* clear buffer */
                sprintf(created_pass, "");
                /* second_word first_word */
                change_string_by_id(local_id, &first_word);
                change_string_by_id(local_id, &second_word);
                strcat(created_pass, first_word);
                strcat(created_pass, second_word);
                pthread_rwlock_rdlock(&tsd_rwlock);
                check_passwords(created_pass, my_tsd, global_id);
                pthread_rwlock_unlock(&tsd_rwlock);
                /* clear buffer */
                sprintf(created_pass, "");
                /* with separator */
                for(int k = 0; k < strlen(separators) && running; k++)
                {
                    /* first_word second_word */
                    change_string_by_id(local_id, &first_word);
                    change_string_by_id(local_id, &second_word);
                    strcat(created_pass, first_word);
                    strncat(created_pass, &(separators[k]), 1);
                    strcat(created_pass, second_word);
                    pthread_rwlock_rdlock(&tsd_rwlock);
                    check_passwords(created_pass, my_tsd, global_id);
                    pthread_rwlock_unlock(&tsd_rwlock);
                    /* clear buffer */
                    sprintf(created_pass, "");
                    /* second_word first_word */
                    change_string_by_id(local_id, &first_word);
                    change_string_by_id(local_id, &second_word);
                    strcat(created_pass, first_word);
                    strncat(created_pass, &(separators[k]), 1);
                    strcat(created_pass, second_word);
                    pthread_rwlock_rdlock(&tsd_rwlock);
                    check_passwords(created_pass, my_tsd, global_id);
                    pthread_rwlock_unlock(&tsd_rwlock);
                    /* clear buffer */
                    sprintf(created_pass, "");
                }
                free(second_word);
            }
            free(first_word);
        }
    }
    printf("cracking thread %u: exit\n", global_id);
    pthread_exit(NULL);
}

/* thread that cracks passwords, thread cracks passwords containing only numbers */
void *cracking_thread_numbers(void *arg)
{
    struct thread_shared_data* my_tsd;
    my_tsd = (struct thread_shared_data*) arg;
    unsigned int id = 3;

    unsigned long num = 0;
    char num_buf[11]; // unsigned long range [0, 4294967295] -> 10 chars + '/0'
    while(running)
    {
        if(reset)
            reset_thread(id, &num, NULL, NULL);
        sprintf(num_buf, "%lu", num);
        pthread_rwlock_rdlock(&tsd_rwlock);
        check_passwords(num_buf, my_tsd, id);
        pthread_rwlock_unlock(&tsd_rwlock);
        if(num == U_LONG_MAX) num = 0;
        else num++;
    }
}

/* function opens a file of given name, create dynamic array containing all lines of file that can be accessed by
 * pointer given in argument, also size can be accessed similarly
 * returns 0 if succeed otherwise -1 */
int read_file(char * file_name, char *** container_ptr, unsigned long * size)
{
    FILE * file = fopen(file_name, "r");
    if(file == NULL) return -1;
    char *str = (char*)malloc(BUF_SIZE*sizeof(char));
    *size = 0;
    while(fscanf(file, "%[^\r\n] ", str) != EOF)
    {
        *container_ptr = realloc(*container_ptr, (++(*size)) * sizeof(char *));
        (*container_ptr)[*size - 1] = (char*)malloc((strlen(str)+1)*sizeof(char));
        strcpy((*container_ptr)[*size - 1], str);
    }
    free(str);
    pclose(file);

    return 0;
}


int main(int argc, char * argv[])
{
    pthread_t threads[NUM_THREADS];
    struct thread_shared_data tsd;
    tsd.dict_ptr = NULL;
    tsd.pass_ptr = NULL;
    tsd.br_pass_ptr = NULL;
    tsd.is_cracked_ptr = NULL;
    tsd.br_pass_size = 0;
    tsd.basic_thread_count = 0;
    tsd.two_word_thread_count = 0;

    /* check if arguments were given*/
    if(argc <= 1)
    {
        printf("main: passwords_file argument not given\n");
        printf(USAGE);
        exit(1);
    }

    /* read dictionary into memory */
    /* check if dictionary was given in arguments */
    if(argc >= 3)
    {
        if(read_file(argv[2], &tsd.dict_ptr, &tsd.dict_size) == -1)
        {
            printf("main: dictionary file: %s not found\n", argv[2]);
            exit(1);
        }
    }
    else /* read default dictionary */
    if(read_file(DEFAULT_DICTIONARY, &tsd.dict_ptr, &tsd.dict_size) == -1)
    {
        printf("main: default dictionary file: %s not found\n", DEFAULT_DICTIONARY);
        printf(USAGE);
        exit(1);
    }

    /* read hashed passwords into memory */
    if(read_file(argv[1], &tsd.pass_ptr, &tsd.pass_size) == -1)
    {
        printf("main: passwords file: %s not found\n", argv[1]);
        exit(1);
    }
    else /* allocate is password cracked array and initialize all bits to zero == false */
        tsd.is_cracked_ptr = (bool *)calloc(tsd.pass_size, sizeof(bool));

    /* signal handling */
    signal(SIGINT, quit_program);
    signal(SIGHUP, print_statistics);

    /* create threads and initialise mutex, cond value and read write lock */
    pthread_mutex_init(&cond_mutex, NULL);
    pthread_mutex_init(&count_mutex, NULL);
    pthread_cond_init (&pass_cracked_cv, NULL);
    pthread_rwlock_init(&tsd_rwlock, NULL);
    pthread_create(&threads[0], NULL, consumer_thread, (void*) &tsd);
    pthread_create(&threads[1], NULL, cracking_thread_numbers, (void *) &tsd);
    for(int i = 2; i < NUM_THREADS; i+=2)
    {
        pthread_create(&threads[i], NULL, cracking_thread_basic, (void *) &tsd);
        pthread_create(&threads[i + 1], NULL, cracking_thread_two_words, (void *) &tsd);
    }

    /* main loop reading user input */
    char *input = (char*)malloc(BUF_SIZE*sizeof(char));
    char ** tmp_ptr = NULL;
    unsigned long tmp_size = 0;
    while(running)
    {
        printf("main: waiting for input:\n");
        scanf("%s", input);
        if(!strcmp(input, "exit")) quit_program();
        else if(!strcmp(input, "stats")) print_statistics();
        else
        {
            if(read_file(input, &tmp_ptr, &tmp_size) == -1)
                printf("main: passwords file %s not found\n", input);
            else
            {
                /* reset */
                printf("main: new passwords file loaded\n");
                reset = true;
                pthread_rwlock_wrlock(&tsd_rwlock);
                printf("main: reset\n");
                print_statistics();
                for(unsigned long i = 0; i < tsd.pass_size; i++) free(tsd.pass_ptr[i]);
                free(tsd.pass_ptr);
                for(int i = 0; i < tsd.br_pass_size; i++) free(tsd.br_pass_ptr[i]);
                free(tsd.br_pass_ptr);
                tsd.br_pass_ptr = NULL;
                tsd.pass_ptr = tmp_ptr;
                tsd.pass_size = tmp_size;
                tmp_ptr = NULL;
                free(tsd.is_cracked_ptr);
                tsd.is_cracked_ptr = (bool *)calloc(tsd.pass_size, sizeof(bool));
                tsd.br_pass_size = 0;
                printf("main: start\n");
                reset = false;
                pthread_rwlock_unlock(&tsd_rwlock);
            }
        }
    }
    free(input);

    /* cleaning the program */
    pthread_mutex_destroy(&count_mutex);
    pthread_mutex_destroy(&cond_mutex);
    pthread_cond_destroy(&pass_cracked_cv);
    pthread_rwlock_destroy(&tsd_rwlock);

    printf("main: freeing memory\n");
    /* free dictionary array */
    for(unsigned long i = 0; i < tsd.dict_size; i++)
        free(tsd.dict_ptr[i]);

    free(tsd.dict_ptr);
    /* free passwords array*/
    if(tsd.pass_ptr != NULL)
    {
        for(unsigned long i = 0; i < tsd.pass_size; i++)
            free(tsd.pass_ptr[i]);

        free(tsd.pass_ptr);
    }
    /* free broken passwords array */
    if(tsd.br_pass_ptr != NULL)
        for(unsigned long i = 0; i < tsd.br_pass_size; i++)
            free(tsd.br_pass_ptr[i]);

    free(tsd.br_pass_ptr);
    /* free is broken array */
    free(tsd.is_cracked_ptr);

    printf("main: exit\n");
    pthread_exit(NULL);
}
