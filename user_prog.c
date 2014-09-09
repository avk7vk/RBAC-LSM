/*
 * SBRBAC Linux Security Module - USER MODULE
 *
 * Author: Vamsi Krishna Atluri <vamsikrishna.atluri@stonybrook.edu>
 * ID    : 109597320
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h> //mode_t
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BUF_SIZE 4096


void print_help();
int add_user_to_role(int ruid, char *role);
void read_user_to_role();
int delete_user_to_role(int ruid, char *role) ;
int assign_active_role(int ruid, char *role) ;
int add_rule_to_role(char *role, char* func, char *file_name, int eflag);
void readall_rule_to_role(char *role) ;
int delete_rule_to_role(char *role, char* func, char *file_name) ;
int add_domains(char *file_name) ;


void disp_error() {

	printf("Invalid Arguments\n");
  print_help();
	exit(1);
}
int main(int argc, char *argv[])
{
	int c =0; 

	if(argc == 1) {
    print_help();
		exit(1);
	}
    switch(c = (int) strtol(argv[1], NULL , 10)){
   		 
   		 /*Add User to a Role */
   		 case 1 :printf("Adding a Role\n");
   		 		if(argc !=4)
   		 			disp_error();
   		 		{
   		 			int usr_id = (int) strtol(argv[2],NULL , 10);
   		 			char * role = argv[3];
   		 			printf("uid : %d Role : %s \n", usr_id, role);
   		 			add_user_to_role(usr_id, role);
   		 		}
           		 break;   
   		 		
         /*Add a Role/ to a Role */  		 
  		 case 2 :printf("Adding a Rule to Role\n");
           		 if(argc !=6)
   		 			disp_error();
           	{
       		 			char* role = argv[2];
       		 			char* func = argv[3];
       		 			char* fname = argv[4];
                int eflag = (int) strtol(argv[5], NULL,10);
       		 			printf("Role : %s Function : %s File Name : %s eflag :%d\n"
                  ,role, func, fname, eflag);
                add_rule_to_role(role, func, fname,eflag);
   		 		  }
           		 break;   
         /* Delete a Role */
         case 3 : printf("Delete a Role\n"); 
         			if(argc !=4)
            disp_error();
          {
            int usr_id = (int) strtol(argv[2],NULL , 10);
            char * role = argv[3];
            printf("uid : %d Role : %s \n", usr_id, role);
            delete_user_to_role(usr_id, role);
          }
               break;
         /* Delete a rule from a Role */
         case 4 : printf("Delete a Rule\n"); 
         			   if(argc !=5)
            disp_error();
            {
                char* role = argv[2];
                char* func = argv[3];
                char* fname = argv[4];
                printf("Role : %s Function : %s File Name : %s\n",role, func, fname);
                delete_rule_to_role(role, func, fname);
            }
               break;  
          /* Read all user -> roles */
         case 5 : printf("Read User Roles a Rule\n"); 
         			if(argc !=2)
   		 				disp_error();
         			read_user_to_role();
         			break;
          /* Read all roles -> rules */
         case 6 : printf("Read Roles to Rule\n"); 
              if(argc !=3)
              disp_error();
            {
              char *role = argv[2];
              readall_rule_to_role(role);
             }
              break;
          /*Add a domain */       
       case 7 :printf("Adding a dir to Domains\n");
               if(argc !=3)
            disp_error();
            {
                char* fname = argv[2];
                printf("File Name : %s\n",fname);
                add_domains(fname);
            }
               break; 
        /* Assign active Role */
         case 8 : printf("Assign Active Role\n"); 
              if(argc !=4)
            disp_error();
          {
            int usr_id = (int) strtol(argv[2],NULL , 10);
            char * role = argv[3];
            printf("uid : %d Role : %s \n", usr_id, role);
            assign_active_role(usr_id, role) ;
          }
               break;

         default:
         printf("Invalid Option : %d\n", c);
         print_help();
  	 }

  	 return 0;
}

int add_user_to_role(int ruid, char *role) 
{	
	int sourceFile;
	unsigned int slen = (21 * sizeof(char));
	unsigned int ruid_sz = sizeof(int);
	unsigned int rec_size = ruid_sz + slen + ruid_sz;
  int act_role = 0;
    void* buf = (void *)malloc(rec_size);
    int wrBytes = 0;

    sourceFile = open("/etc/rbac/users", O_RDWR|O_CREAT|O_APPEND, 00755);
    
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        return -1;
    }
    printf("Int ruid size %d\n", sizeof(int));
    memcpy(buf, (void *) &ruid, ruid_sz);
    memcpy((buf + ruid_sz), role, strlen(role) + 1);
    memcpy((buf + ruid_sz + slen), &act_role, ruid_sz);
    printf("ruid : %d role : %s active role :%d\n", *(int*)buf, 
      (char *)(buf + (ruid_sz)), *(int *)(buf + ruid_sz + slen) );
    wrBytes = write(sourceFile, buf, rec_size);
    if ( wrBytes != rec_size){
    	printf("Partial Write Error\n");
    	close(sourceFile);
      return -1;
    }
    assign_active_role(ruid, role);
    close(sourceFile);
    return 0;

}
void read_user_to_role()
{	
	int sourceFile;
	unsigned int slen = (21 * sizeof(char));
	unsigned int ruid_sz = sizeof(int);
	unsigned int rec_size = ruid_sz + slen + ruid_sz;
    void* buf = (void *)malloc(rec_size);
    int ruid = 0, act_role = 0;
    char *role = (char *) malloc(slen);
    int rdBytes = 0;

    sourceFile = open("/etc/rbac/users", O_RDONLY);
    
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        disp_error();
    }
    printf("******USER - ROLE*******\n");
    while((rdBytes = read(sourceFile, buf, rec_size)) > 0){
	    if ( rdBytes != rec_size){
	    	printf("Partial Read Error\n");
	    	disp_error();
	    }

	    memcpy(&ruid, buf, ruid_sz);
	    memcpy(role, (buf + (ruid_sz)), slen);
      memcpy(&act_role, (buf + (ruid_sz) + slen), ruid_sz);
	    printf("ruid : %d role : %s act_role : %d\n", ruid, (char *)(buf + ruid_sz), act_role);
    };
    close(sourceFile);
    free(buf);
}

int delete_user_to_role(int ruid, char *role) 
{ 
  int sourceFile, newFile;
  unsigned int slen = (21 * sizeof(char));
  unsigned int ruid_sz = sizeof(int);
  unsigned int rec_size = ruid_sz + slen + ruid_sz;
  void* buf = (void *)malloc(rec_size);
  int rdBytes = 0, wrBytes = 0;
  char * tmp_name = NULL;
  
  printf("**********In delete user role**********\n");
  sourceFile = open("/etc/rbac/users", O_RDONLY);
    
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        disp_error();
    }

  if(!(tmp_name = tempnam("/etc/rbac/", "XXXXX"))) {
      printf("Error Creating tmp File Name\n");
      return -1;
  }
  printf("Temp File name :%s \n", tmp_name);
  newFile = open(tmp_name, O_RDWR|O_CREAT, 00755);
    
  if(newFile < 0)
  {
        printf("Error opening Tmp file %d\n", newFile);
        return -1;
  }
    
  while((rdBytes = read(sourceFile, buf, rec_size)) > 0){
    if ( rdBytes != rec_size){
      printf("Partial Read Error\n");
      disp_error();
    }
    if((ruid == *(int *)buf) && !strcmp(role, (char *)buf+ruid_sz)) {
      printf("Found! ruid : %d role : %s act_role :%d\n", ruid, 
        role, *(int *)(buf+ruid_sz +slen));
      continue;
    }
    wrBytes = write(newFile, buf, rec_size);
    if ( wrBytes != rdBytes){
      printf("Partial Write Error\n");
      disp_error();
    }
      
  }
  close(sourceFile);
  close(newFile);
  
  if(remove("/etc/rbac/users")) {
    printf("Error in removing old users file\n");
    return -1;
  }
  if(rename(tmp_name, "/etc/rbac/users")) {
    printf("Error in removing old users file\n");
    return -1;
  }
  free(buf);
  return 0;
}

int assign_active_role(int ruid, char *role) 
{ 
  int sourceFile;
  unsigned int slen = (21 * sizeof(char));
  unsigned int ruid_sz = sizeof(int);
  unsigned int rec_size = ruid_sz + slen + ruid_sz;
  void* buf = (void *)malloc(rec_size);
  int rdBytes = 0, wrBytes = 0;
  
  printf("**********Assign Active Role**********\n");
  sourceFile = open("/etc/rbac/users", O_RDWR);
    
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        disp_error();
    }

  while((rdBytes = read(sourceFile, buf, rec_size)) > 0){
    if ( rdBytes != rec_size){
      printf("Partial Read Error\n");
      disp_error();
    }
    if((ruid == *(int *)buf)) {
      printf("Found! ruid : %d role : %s act_role : %d\n", ruid, role, 
        *(int *)(buf + ruid_sz + slen));
      
      if(!strcmp(role, (char *)(buf+ruid_sz))) {
        *(int *)(buf + ruid_sz + slen) = 1;
      }
      else {
        *(int *)(buf + ruid_sz + slen) = 0;
      }
      lseek(sourceFile, (off_t) (- rec_size), SEEK_CUR);
      wrBytes = write(sourceFile, buf, rec_size);
      if ( wrBytes != rec_size){
        printf("Partial Write Error\n");
        disp_error();
      }

    }
          
  }
  close(sourceFile);
  free(buf);
  return 0;
}
int add_rule_to_role(char *role, char* func, char *file_name, int eflag) 
{	
	int sourceFile;
  unsigned int eflag_sz = sizeof(int);
	unsigned int ino_sz = sizeof(unsigned long);
	unsigned int slen = (21 * sizeof(char));
	unsigned int rec_size = ino_sz + slen + slen + eflag_sz;
  void* buf = (void *)malloc(rec_size);
  int wrBytes = 0;
  char role_file[50];
  struct stat ino_stat;
  unsigned long ino = 0;
  int err=0;

  strcpy(role_file, "/etc/rbac/roles/");
  strcat(role_file, role);
  if((err = stat(file_name, &ino_stat))) {
    printf("Error occured in stating File_name: %s Error :%d\n", file_name, err);
    goto exit_err;
  }
  ino = (unsigned long)ino_stat.st_ino;
  printf("ROLE file : %s Inode number is %ld \n", role_file, (long)ino_stat.st_ino);

  sourceFile = open(role_file, O_RDWR|O_CREAT|O_APPEND, 00755);
    
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        return -1;
    }
    printf("Int func size %d\n", sizeof(int));
    memcpy(buf , func, strlen(func)+1);
    memcpy(buf + slen , &ino, ino_sz);
    memcpy(buf + slen + ino_sz ,file_name, strlen(file_name)+1);
    memcpy(buf + slen + ino_sz + slen ,&eflag, eflag_sz);
    printf("role : %s func : %s file name : %s "
     "file  inode: %lu eflag :%d \n", role, (char *)buf,(char *)(buf + slen+ino_sz),
      *(unsigned long *)(buf + (slen)), 
      *(int *)(buf + (slen+ino_sz+slen)));

    wrBytes = write(sourceFile, buf, rec_size);
    if ( wrBytes != rec_size){
    	printf("Partial Write Error\n");
      close(sourceFile);
    	return -1;
    }
    exit_err:
    close(sourceFile);
    free(buf);
  return 0;

}

void readall_rule_to_role(char *role) 
{ 
  int sourceFile;
  unsigned int eflag_sz = sizeof(int);
  unsigned int ino_sz = sizeof(unsigned long);
  unsigned int slen = (21 * sizeof(char));
  unsigned int rec_size = slen + ino_sz + slen + eflag_sz;
  void* buf = (void *)malloc(rec_size);
  int rdBytes = 0;
  char role_file[50];
  strcpy(role_file, "/etc/rbac/roles/");
  strcat(role_file, role);

  printf("ROLE file : %s\n", role_file);
  sourceFile = open(role_file, O_RDONLY);
    
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        return ;
    }
    printf("**********For the Role : %s ********\n", role);
    while((rdBytes = read(sourceFile, buf, rec_size)) > 0) {
      if ( rdBytes != rec_size){
        printf("Partial Read Error\n");
        close(sourceFile);
        return ;
      }
      printf("func : %s file ino: %lu file_name: %s eflag:%d\n", (char *)buf, 
        *(unsigned long *)(buf + (slen)), (char *)(buf + slen + ino_sz), 
        *(int *)(buf + slen + ino_sz+slen));
    }
  close(sourceFile);
  return;

}

int delete_rule_to_role(char *role, char* func, char *file_name) 
{ 
  int sourceFile, newFile;
  unsigned int eflag_sz = sizeof(int);
  unsigned int ino_sz = sizeof(unsigned long);
  unsigned int slen = (21 * sizeof(char));
  unsigned int rec_size = slen + ino_sz + slen +eflag_sz;
  void* buf = (void *)malloc(rec_size);
  int rdBytes = 0, wrBytes = 0, err = 0;
  char * tmp_name = NULL;
  char role_file[50];
  unsigned long ino = 0;
  struct stat ino_stat;

  strcpy(role_file, "/etc/rbac/roles/");
  strcat(role_file, role);
  printf("**********In delete rule in role**********\n");
  if((err = stat(file_name, &ino_stat))) {
    printf("Error occured in stating File_name: %s Error :%d\n", file_name, err);
    return -1;
  }
  ino = (unsigned long)ino_stat.st_ino;
  printf("ROLE file : %s file name : %s inode : %lu \n", role_file, file_name, ino);

  sourceFile = open(role_file, O_RDONLY);
    
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        disp_error();
    }

  if(!(tmp_name = tempnam("/etc/rbac/roles/", "XXXXX"))) {
      printf("Error Creating tmp File Name\n");
      return -1;
  }
  printf("Temp File name :%s \n", tmp_name);
  newFile = open(tmp_name, O_RDWR|O_CREAT, 00755);
    
  if(newFile < 0)
  {
        printf("Error opening Tmp file %d\n", newFile);
        return -1;
  }
    
  while((rdBytes = read(sourceFile, buf, rec_size)) > 0){
    if ( rdBytes != rec_size){
      printf("Partial Read Error\n");
      disp_error();
    }
    if(!strcmp(func, (char *)buf) && (ino == *(unsigned long*)(buf+slen))) {
      printf("Found! func : %s inode : %lu file :%s eflag :%d\n", (char *)buf, ino,
        (char *)(buf + slen +ino_sz), *(int *)(buf + slen +ino_sz+slen));
      continue;
    }
    wrBytes = write(newFile, buf, rec_size);
    if ( wrBytes != rdBytes){
      printf("Partial Write Error\n");
      disp_error();
    }
      
  }
  close(sourceFile);
  close(newFile);
  
  if(remove(role_file)) {
    printf("Error in removing old role file\n");
    return -1;
  }
  if(rename(tmp_name, role_file)) {
    printf("Error in renaming tmp  role file\n");
    return -1;
  }
  free(buf);
  return 0;

}

int add_domains(char *file_name) 
{ 
  int sourceFile;
  unsigned int ino_sz = sizeof(unsigned long);
  unsigned int slen = (21 * sizeof(char));
  unsigned int rec_size = ino_sz + slen;
  void* buf = (void *)malloc(rec_size);
  int wrBytes = 0;
  struct stat ino_stat;
  unsigned long ino = 0;
  int err=0;

  if((err = stat(file_name, &ino_stat))) {
    printf("Error occured in stating File_name: %s Error :%d\n", file_name, err);
    goto exit_err;
  }
  ino = (unsigned long)ino_stat.st_ino;
  printf("Dir : %s Inode number is %ld \n", file_name, (long)ino_stat.st_ino);

  sourceFile = open("/etc/rbac/dir_domains", O_RDWR|O_CREAT|O_APPEND, 00755);
    
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        return -1;
    }
    memcpy(buf , &ino, ino_sz);
    memcpy(buf + ino_sz ,file_name, strlen(file_name)+1);

    printf("file name : %s file  inode: %lu \n", (char *)(buf + ino_sz),
      *(unsigned long *)(buf ));
    wrBytes = write(sourceFile, buf, rec_size);
    if ( wrBytes != rec_size){
      printf("Partial Write Error\n");
      close(sourceFile);
      return -1;
    }
    exit_err:
    close(sourceFile);
    free(buf);
  return 0;

}

void print_help() 
{
  printf("**********************SBRBAC ADMIN MODULE ************************\n\n");
  printf("1) ./user_prog 1 <uid> <role> - Assign a Role to User \n\n");
  printf("2) ./user_prog 2 <role> <func_name> <file/dir>  <0|1> - Assign a Policy to a Role \n\n");
  printf("3) ./user_prog 3 <uid> <role> - Delete a User from a Role \n\n");
  printf("4) ./user_prog 4 <role> <func_name> <file/dir> - Delete a Policy from a Role \n\n");
  printf("5) ./user_prog 5 - Read All User to ROles Mapping \n\n");
  printf("6) ./user_prog 6 <role> - Read All policies belonging to a Role \n\n");
  printf("7) ./user_prog 7 <dir> - Assign a Dir to Domain of SBRBAC \n\n");
  printf("8) ./user_prog 8 <uid> <role> - Assign an Active role user \n\n");

}