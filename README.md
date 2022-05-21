# Passwords_Cracker
  Simple multithread app for performing dictionary attack on given md5 hashed passwords. Every thread generates password type.
  
## Thread Description
It creates 8 threads in total, first thread (consumer) receives cracked passwords from cracking threads and then prints it,
this thread is communicating with other threads by conditional value. Other threads generate passwords using given or default
dictionary, every thread is generating passwords using different method. Three basic cracking threads create passwords from different latter cases and adds
numbers before or/and after generated word. Another three threads generate two word passwords separated by " ", "2", "4" or nothing,
words are modified same as in basic threads. The last thread generates numeric passwords. Main loop is reading user input.

## User input
`stats` or `SIGHUP` signal -> print statistics  
`path to new passwords file` -> reset program (also prints stats)  
`exit` or `SIGINT` signal (CTRL + C) - > exit program (after `SIGINT` typing any key is required)  


## Getting started
### Prerequisites
#### 1. pthread library
```bash
sudo apt-get install libpthread-stubs0-dev
```
#### 2. open-ssl library
```bash
sudo apt-get install openssl libssl-dev
```
#### 3. download dictionaries (optional)  
   `InsidePro (Mini)` dictionary is included.  
   Other dictionaries can be found here https://web.archive.org/web/20120207113205/http://www.insidepro.com/eng/download.shtml
   
#### 4. download md5 hashed passwords (optional)
  Sample passwords are included in this repos, but more can be found at http://pastebin.com
   
## Compile and run
```bash
make
./pass_cr <password file> [dictionary file]
```

## Example
```bash
./pass_cr passwords1.txt

consumer thread: cracked password received: thomas
cracking thread 0: password broken -> topgun
consumer thread: cracked password received: topgun
cracking thread 0: password broken -> trigger
consumer thread: cracked password received: trigger
cracking thread 0: password broken -> trinity
consumer thread: cracked password received: trinity
cracking thread 0: password broken -> troutt
consumer thread: cracked password received: troutt
cracking thread 0: password broken -> victoria
consumer thread: cracked password received: victoria
cracking thread 0: password broken -> vision
consumer thread: cracked password received: vision
cracking thread 0: password broken -> whatever
consumer thread: cracked password received: whatever
cracking thread 0: password broken -> whiskey
cracking thread 0: password broken -> wolverine
consumer thread: cracked password received: wolverine
cracking thread 3: password broken -> 281091
consumer thread: cracked password received: 281091
stacracking thread 3: password broken -> 449717
consumer thread: cracked password received: 449717
tscracking thread 1: password broken -> Charlie1
consumer thread: cracked password received: Charlie1

main: waiting for input:
consumer thread: stats -> cracked 79 of 321  24.61%
```
