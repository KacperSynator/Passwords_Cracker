all: pass_cr help

pass_cr: main.c
	gcc -w -o pass_cr main.c -pthread -lssl -lcrypto # -w ignore warnings

help:
	@echo "usage: \033[1m./pass_cr\033[0m passwords_file [dictionary_file]"
	
	
clean:
	rm pass_cr
