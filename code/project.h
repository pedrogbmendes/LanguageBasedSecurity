/*****************************************************************************
*
*                       Language-based Security
*
*   Project: Exploit Vulnerabilities in in UNIX-based Authentication Systems
*
*   Author: Pedro Gonçalo Bravo Mendes - pedrogo@student.chalmers.se
*           Group 32
*
*
******************************************************************************/

#ifndef PROJECT_H
#define PROJECT_H

//INCLUDES
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include <pthread.h>

//DEFINES
#define LENGTH 64

#define LINE_BUFFER_SIZE 1000
#define FILENAME "passwd"
#define FILENAME_AUX "passwdaux"

#define TEMP_BLOCKED 3
#define BLOCK_FOREVER 7

//password struct
typedef struct _passwdInfo{
	char *username;        // Username
  char *password;        // Password
	int uid;               //User id
	char *PasswordSalt;    // Make dictionary attack harder
	int PasswordFailed;    // Number of failed attempts
	int PasswordAge;       // Age of password in number of logins
	int guid;							 // Group uid
	char *UIDinfo;				 // UID info (eg: full name)
	char *home_dir;				 // User home directory
	char *login_shell;		 // Login shell
}PasswdInfo;

//functions
int InitializeSystem(PasswdInfo **password_data);
char *RequestPassword(PasswdInfo *passwd);
int HandlePassword(PasswdInfo *passwd ,char* encrypt_pass);
PasswdInfo *VerifyUsername (char *username);
int UpdatePassInfo(char *username, PasswdInfo *passUp);
int BlockAccount(PasswdInfo *passwd);
void *UserBlock(void *name);
void*VerifyBlocked ();
char *NewPassword(PasswdInfo *passwd);

#endif
