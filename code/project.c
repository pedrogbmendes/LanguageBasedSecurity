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

//INCLUDES
#include "project.h"

//ALARMS
void sighandler() {
	//sighandler to ignore keyboard interruptions
	signal(SIGINT, SIG_IGN);		//ignore crtl+C
	signal(SIGTSTP, SIG_IGN);		//ignore crtl+Z
}


//main
int main(int argc, char const *argv[]) {

// Variables
  PasswdInfo *password_data =  NULL;

  int valid = 0, err;
  char *passwd;

  sighandler();

  //Initializing the system
  printf("The system is initializing\n");

  while (1) {

    valid = InitializeSystem(&password_data);

    if (valid == 0){
      /*username is incorrect. however the user doesn't be warm that the username
      is incorrect.
      user should write the username and then the password and only after that
      the system must print an error alerting that username and/or password are
      incorrect*/

      passwd = RequestPassword(password_data);
      printf("Login incorrect: The username and/or the password are incorrect\nTry again\n");


    }else if (valid == 1){
      //username exists in the system

      if(password_data->PasswordFailed == BLOCK_FOREVER){
        /*the user account is blocked forever, because he wrotes the wrong
        password to many times*/
        printf("Your account is blocked. You have to contact the administrator.\n");

      }else if(password_data->PasswordFailed == TEMP_BLOCKED){
        /*the user wrote the wrong password 3 times, so the account is tempo-
        rarily blocked. The user has to wait until be possible access again
        to his account*/
        printf("Your account is temporarily blocked. You have to wait\n");


      }else{
        passwd = RequestPassword(password_data);
        err =  HandlePassword(password_data , passwd);
        if (err == -1){
           printf("ALERT: ERROR!!!\nUpdating the file (UpdatePassInfo)\n");
        }

      }

    }

  }
  return 0;
}
