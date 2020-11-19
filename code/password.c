/*****************************************************************************
*
*                       Language-based Security
*
*   Project: Exploit Vulnerabilities in in UNIX-based Authentication Systems
*
*   Author: Pedro Gonçalo Bravo Mendes - pedrogo@student.chalmers.se
*           Group 32
*
*   PASSWORD.C file
*
*   The functions are explained below
******************************************************************************/


//INCLUDES
#include "project.h"

//GLOBAL VARIABLES
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


/***************************************************************************

      InitializeSystem(PasswdInfo **password_data)

      goal: function where the user writes the username and the system verify
      if the username is valid or not

      arguments: struct password_data

      return value: returns a int value:
                        - 1 in case of success (unsername exists)
                        - 0 in case of insuccess (unsername doesn't exist)
                        - -1 in case of error

***************************************************************************/

int InitializeSystem(PasswdInfo **password_data){

  char user[LENGTH];
  char user_check[LENGTH];

  printf("\n\tLogin:\t");

  //handle with bufferoverflows
  if (fgets(user_check, LENGTH, stdin) == NULL){
    //error message
    printf("An error occurred in the system. Please initialize the system again\n");
    return -1;
  }

  sscanf(user_check, "%s", user);

  *password_data = VerifyUsername(user);
  if(*password_data == NULL){
      //username doesn't exist
      return 0;
  }

  return 1;
}

/***************************************************************************/




/***************************************************************************

      *RequestPassword(PasswdInfo *passwd)

      goal: function where the user writes the password and it's encrypted with
      an hash function (using a salt)

      arguments: struct passwd

      return value:
                  - the encrypted password (written by the user)
                  - NULL in case of error

***************************************************************************/

char *RequestPassword(PasswdInfo *passwd){

  char string_bash[] = "\n\tpassword: ";
  char salt[2];
  char *encrypt_pass;
  char *password;


  /*this function waits for the input (user writes the password)
  the charecters are hidden in the terminal */
  password = getpass(string_bash);

  /*            encryption of the password
    the encryption is done using a hash function (crypt) for security reasons
  so it's possible do encrypt the password then to be compared with the
  password in the file, but is not possible to decrypt a password

    in crypt function a salt is used (salt is a two-character string chosen
  from the set [a-zA-Z0-9./].  This string is used to perturb the algorithm
  in  one of 4096 different ways.

    the strncpy is used to copy the salt from the file and to prevent a buffer
  overflow attack, that could exploit this weakness

  */
  if (passwd != NULL){
    strncpy(salt, passwd->PasswordSalt, 2);
    encrypt_pass = crypt(password, salt);
    return encrypt_pass;
  }
  return NULL;
}

/**************************************************************************/




/***************************************************************************

      *NewPassword(PasswdInfo *passwd)

      goal: function where the user writes the new password.
      the function verifies if the all the caracters are acceptable and
      if is not a empty string (no password).
      If the password does not fulfill the requeriments the user has to write
      a new one.

      arguments: struct passwd

      return value:
            - the new encrypted password
            - NULL in case of error

***************************************************************************/

char *NewPassword(PasswdInfo *passwd){


  char string_bash[] = "\n\tpassword: ";
  char salt[2];
  char *encrypt_pass;
  char *password;
  int valid = 0, i;

  password = getpass(string_bash);

  while(valid != 1){

    if(strlen(password) < 6){
        valid = -1;
    }

    for(i=0; i<strlen(password); i++){
      if(password[i] < 33 || password[i] > 126)
        valid = -1;
    }

    if(strcmp(password, "") == 0 )
      valid = -1;

    if(valid != -1){
      valid = 1;
    }else{
      password = "";
      valid = 0;
      printf("Password not permited.\n");
      password = getpass(string_bash);
    }
  }


  if (passwd != NULL){
    strncpy(salt, passwd->PasswordSalt, 2);
    encrypt_pass = crypt(password, salt);

    return encrypt_pass;
  }
  return NULL;
}

/**************************************************************************/




/***************************************************************************

       HandlePassword(PasswdInfo *passwd ,char* encrypt_pass)

       goal: verifies if the password id correct.
       if yes, a new shell is initialize
       if no, handles the account depending of specific aspects

       arguments: struct passwd and the encrypted password written by the user
       (in the moment of login)

       return value:
              - if the password is correct does not return anything and starts
          a new shell.
              - 0 if the password is wrong
              - -1 in case of error

***************************************************************************/

int HandlePassword(PasswdInfo *passwd ,char* encrypt_pass){

  int err=0;

  if (strcmp(encrypt_pass, passwd->password) == 0){
    //right password

    passwd->PasswordAge++;

    if(passwd->PasswordAge > 10){
      //password is too old
      printf("You have to change the password (your password is too old).\n");
			printf("Entry the new password:\n");

      encrypt_pass = NewPassword(passwd);

      while( (strcmp(encrypt_pass, passwd->password) == 0)) {
        printf("The new password has to be different from the old one.\nEntry the new password:\n");
        encrypt_pass = NewPassword(passwd);
      }

      passwd->password = encrypt_pass;
      passwd->PasswordAge = 1;

    }else if ( passwd->PasswordFailed > TEMP_BLOCKED ) {
      //user failed the first 3 tries so when it login again has to change password
      printf("For security reasons you have to change your password.\nYour account probabily was been compromised\n");
      printf("Entry the new password:\n");

      encrypt_pass = NewPassword(passwd);
      while(strcmp(encrypt_pass, passwd->password) == 0 ){
        printf("The new password has to be different from the old one.\nEntry the new password:\n");
        encrypt_pass = NewPassword(passwd);
      }
      passwd->password = encrypt_pass;
      passwd->PasswordAge = 1;
    }
    passwd->PasswordFailed = 0;

    //updates the passwd file
   err = UpdatePassInfo(passwd->username, passwd);
    if(err == -1){
      printf("ALERT: ERROR!!!\nUpdating the file (UpdatePassInfo)\n");
      return -1;
    }

    // check UID
    if(setuid(passwd->uid) != 0){
      printf("ALERT: ERROR!!!\nThe root cannot login into your acount (setuid)\n");
      return -1;
    }else{
      //login into the account - all requeriments are OK
      printf("Welcome to your system user %s!\n", passwd->username);

      VerifyBlocked();

      //starts a new shell
      char *new[] = {NULL};
      new[0] = passwd->login_shell;
      new[1] = NULL;

      if( execve(passwd->login_shell, new, NULL) == -1){
        printf("ALERT: ERROR!\nOpening the new shell (execve)\n");
        return -1;
      }
    }

  }else{
    //wrong password
    passwd->PasswordFailed++;

    if (passwd->PasswordFailed == BLOCK_FOREVER){
      /*the user account is blocked forever, because he wrotes the wrong
      password to many times*/
      printf("Login incorrect:\nYour account is blocked. You have to contact the administrator.\n");

    }else if (passwd->PasswordFailed == TEMP_BLOCKED){
      /*the user wrote the wrong password 3 times, so the account is tempo-
      rarily blocked. The user has to wait until be possible access again
      to his account*/
      printf("Login incorrect:\nYour account is temporarily blocked. You have to wait\n");

      err = BlockAccount(passwd);
      if (err == -1){
        return -1;
      }

    }else if ( (passwd->PasswordFailed > TEMP_BLOCKED) || (passwd->PasswordFailed < TEMP_BLOCKED) ){
      /*user has the last chances to write the correct password until it blocks
      the account or   user wrote an incorrect password. he has to try again*/
      printf("Login incorrect:The username and/or the password are incorrect\nTry again\n");

    }

    err = UpdatePassInfo(passwd->username, passwd);
    if(err == -1){
      printf("ALERT: ERROR!!!\nUpdating the file (UpdatePassInfo)\n");
      return -1;
    }

  }
  return 0;
}

/**************************************************************************/




/***************************************************************************

      BlockAccount(PasswdInfo *passwd)

      goal: creates a threat to "set an alarm" and block the account during
      a specific time

      arguments: struct passwd

      return value:
            - 0 if successed
            - -1 in case of error

***************************************************************************/

int BlockAccount(PasswdInfo *passwd){

  pthread_t t_block;

  int err = pthread_create(&t_block, NULL, UserBlock, (void*)(passwd->username) );
  if(err != 0) {
    printf("ALERT: ERROR!!!\nError in thread creation\n");
    return -1;
  }
  return 0;
}

/**************************************************************************/




/***************************************************************************

      *UserBlock(void * name)

      goal: blocks the account during a specific time

      arguments: username

***************************************************************************/

void *UserBlock(void * name){

  PasswdInfo *passwd;
  int err = 0;
  char user[LENGTH];
  strcpy(user, ( (char*)name) );

  /*Here in this case an account is blocked during 20 seconds, only because
  to demonstrate the system. In a real system, an account has to be block
  during more time. Depends of each implementation.
  It cannot block during a short period to do not suffer of a brute force
  attack. and it cannot block during a big period to doesn't cause a denial
  of service attack*/

  sleep(20);

  passwd = VerifyUsername(user);
  if(passwd == NULL){
      printf("ALERT: ERROR!!!\nThreads(UpdatePassInfo)\n");

  }else{

    passwd->PasswordFailed = 4;   //UNBLOCKED

    pthread_mutex_lock( &lock );   // RESTRICTED

    err = UpdatePassInfo(passwd->username, passwd);
    if (err == -1){
      printf("ALERT: ERROR!!!\nUpdating the file (UpdatePassInfo)\n");
    }
    pthread_mutex_unlock( &lock );   // END RESTRICTED

  }
  pthread_exit(NULL);

}

/**************************************************************************/
