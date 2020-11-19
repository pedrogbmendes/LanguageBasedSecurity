all: project

project: project.h project.c password.c PassDataBase.c
				gcc -g -Wall project.c password.c PassDataBase.c  -lcrypt -pthread -o project


clean:
				rm -f *.o project
