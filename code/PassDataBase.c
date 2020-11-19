/*****************************************************************************
*
*                       Language-based Security
*
*   Project: Exploit Vulnerabilities in in UNIX-based Authentication Systems
*
*   Author: Pedro Gonçalo Bravo Mendes - pedrogo@student.chalmers.se
*           Group 32
*
*   PassDataBase.C file
*
*   The functions are explained below
******************************************************************************/

//INCLUDES
#include "project.h"


/***************************************************************************

    VerifyUsername(char *username)

    goal: verifies if a username is valid

    arguments: username specified by the user

    return value: pointer to the struct that has the information about
    the specified user (in case of username does not exist return NULL pointer)

****************************************************************************/

PasswdInfo *VerifyUsername (char *username) {

  FILE *fp;
  char buffer[LINE_BUFFER_SIZE];

  static char name[LINE_BUFFER_SIZE], password[LINE_BUFFER_SIZE], pass_salt[LINE_BUFFER_SIZE], uid_info[LINE_BUFFER_SIZE], home[LINE_BUFFER_SIZE], log_shell[LINE_BUFFER_SIZE];
  /*the file passwd cointais the username, the uid, the encrtpted password,
  the salt, the number of failed attempts and the pass's age*/
  static PasswdInfo value = {name, password, 0, pass_salt, 0, 0, 0, uid_info, home, log_shell};

  //open the file
  fp = fopen(FILENAME, "rb");
  if(fp == NULL){
    printf("ALERT: ERROR: File not found\n");
    return NULL;
  }

  //reads each line of the file passwd, looking fot the correct user
  while( fgets(buffer, sizeof(buffer), fp) != NULL ){

    if( sscanf(buffer, "%[^:]:%[^:]:%d:%[^:]:%d:%d:%d:%[^:]:%[^:]:%s", value.username, value.password, &value.uid, value.PasswordSalt, &value.PasswordFailed, &value.PasswordAge, &value.guid, value.UIDinfo, value.home_dir, value.login_shell ) != 10 ){
      fclose(fp);
      return NULL;
    }

    if(strcmp( name, username) == 0){
      //there is a match of username (so the username exists in the system)
      fclose(fp);
      return &value;
    }
  }

  fclose(fp);
  return NULL;

}

/***************************************************************************/




/***************************************************************************

    UpdatePassInfo(char *username, PasswdInfo *passUp)

    goal: update the passwd file

    arguments: username (that the information has to be updated) and
    passUp (strucut type PasswdInfo that contains all the data about the user
    and the respective password)

    return value: in case of success return 1
                  in case of an error return -1 (for example if the user-
            name cannot be found)


****************************************************************************/

int UpdatePassInfo(char *username, PasswdInfo *passUp) {

  FILE *fp;
  FILE *aux_fp;
  int err = 0;

  char line[LINE_BUFFER_SIZE];
  char name[LINE_BUFFER_SIZE];

  //open the file
  fp = fopen(FILENAME, "r");
  if(fp == NULL){
    return -1;
  }
  aux_fp = fopen(FILENAME_AUX, "w");
  if(aux_fp == NULL){
    fclose(fp);
    return -1;
  }

  //reads each line of the file passwd, looking fot the correct user
  while( fgets(line, sizeof(line), fp) != NULL ){
    if(sscanf(line, "%[^:]", name) != 1){
      //error
      fclose(fp);
      fclose(aux_fp);
      unlink(FILENAME_AUX);
      return -1;
    }

    if( strcmp(name, username) == 0){
      // the username is valid - uddate the information
      if( snprintf(line, sizeof(line), "%s:%s:%d:%s:%d:%d:%d:%s:%s:%s\n",passUp->username, passUp->password, passUp->uid, passUp->PasswordSalt, passUp->PasswordFailed, passUp->PasswordAge, passUp->guid, passUp->UIDinfo, passUp->home_dir, passUp->login_shell) >= sizeof(line) ){
        //error
        fclose(fp);
        fclose(aux_fp);
        unlink(FILENAME_AUX);
          return -1;
      }
    }

    //writes a auxiliar file with the updated information
    err = fprintf(aux_fp, "%s", line);
    if(err < 0){
      //error
      fclose(fp);
      fclose(aux_fp);
      unlink(FILENAME_AUX);
      return -1;
    }
  }

  fclose (fp);
  fclose(aux_fp);
  rename(FILENAME_AUX, FILENAME);
  return 0;
}

/***************************************************************************/




/***************************************************************************

    PasswdInfo *VerifyBlocked ()

    goal: verify the blocked accounts

****************************************************************************/

void *VerifyBlocked () {

  FILE *fp;
  char buffer[LINE_BUFFER_SIZE];

  static char name[LINE_BUFFER_SIZE], password[LINE_BUFFER_SIZE], pass_salt[LINE_BUFFER_SIZE], uid_info[LINE_BUFFER_SIZE], home[LINE_BUFFER_SIZE], log_shell[LINE_BUFFER_SIZE];
  /*the file passwd cointais the username, the uid, the encrtpted password,
  the salt, the number of failed attempts and the pass's age*/
  static PasswdInfo value = {name, password, 0, pass_salt, 0, 0, 0, uid_info, home, log_shell};

  //open the file
  fp = fopen(FILENAME, "rb");
  if(fp == NULL){
    printf("ALERT: ERROR: File not found\n");
    return NULL;
  }

  //reads each line of the file passwd, looking fot the correct user
  while( fgets(buffer, sizeof(buffer), fp) != NULL ){

    if( sscanf(buffer, "%[^:]:%[^:]:%d:%[^:]:%d:%d:%d:%[^:]:%[^:]:%s", value.username, value.password, &value.uid, value.PasswordSalt, &value.PasswordFailed, &value.PasswordAge, &value.guid, value.UIDinfo, value.home_dir, value.login_shell ) != 10 ){
      fclose(fp);
      return NULL;
    }

    if(value.PasswordFailed == TEMP_BLOCKED ){
      //there is a match of username (so the username exists in the system)
      value.PasswordFailed = 4;
      UpdatePassInfo(value.username,&value);

    }
  }
  fclose(fp);
  return NULL;

}

/***************************************************************************/
