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

int add_user_to_role(int ruid, char *role);
void read_user_to_role();
int add_rule_to_role(char *role, char* func, char *file_name);
void readall_rule_to_role(char *role) ;

void disp_error() {

	printf("Invalid Arguments\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int c =0; 

	if(argc <= 1) {
		printf("Invalid Arguments\n");
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
           		 if(argc !=5)
   		 			disp_error();
           	{
       		 			char* role = argv[2];
       		 			char* func = argv[3];
       		 			char* fname = argv[4];
       		 			printf("Role : %s Function : %s File Name : %s\n",role, func, fname);
                add_rule_to_role(role, func, fname);
   		 		  }
           		 break;   
         /* Delete a Role */
         case 3 : printf("Delete a Role\n"); 
         			if(argc !=2)
   		 				disp_error();
         			break;
         /* Delete a rule from a Role */
         case 4 : printf("Delete a Rule\n"); 
         			if(argc !=2)
   		 				disp_error();
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
              
         default:printf("Invalid Option : %d\n", c);
  	 }

  	 return 0;
}

int add_user_to_role(int ruid, char *role) 
{	
	int sourceFile;
	unsigned int slen = (21 * sizeof(char));
	unsigned int ruid_sz = sizeof(int);
	unsigned int rec_size = ruid_sz + slen;
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
    memcpy((buf + (ruid_sz)), role, strlen(role) + 1);
    printf("ruid : %d role : %s\n", *(int*)buf, (char *)(buf + (ruid_sz)) );
    wrBytes = write(sourceFile, buf, rec_size);
    if ( wrBytes != rec_size){
    	printf("Partial Write Error\n");
    	close(sourceFile);
      return -1;
    }

    close(sourceFile);
    return 0;

}
void read_user_to_role()
{	
	int sourceFile;
	unsigned int slen = (21 * sizeof(char));
	unsigned int ruid_sz = sizeof(int);
	unsigned int rec_size = ruid_sz + slen;
    void* buf = (void *)malloc(rec_size);
    int ruid = 0;
    char * role = (char *) malloc(slen);
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

	    memcpy((void *) &ruid, buf, ruid_sz);
	    memcpy(role, (buf + (ruid_sz)), slen);
	    printf("ruid : %d role : %s\n", ruid, role);
    };
    close(sourceFile);
}

int add_rule_to_role(char *role, char* func, char *file_name) 
{	
	int sourceFile;
	unsigned int ino_sz = sizeof(unsigned long);
	unsigned int slen = (21 * sizeof(char));
	unsigned int rec_size = ino_sz + slen;
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
    printf("role : %s func : %s file name : %s \
     file  inode: %lu \n", role, (char *)buf,file_name, *(unsigned long *)(buf + (slen)));
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
  unsigned int ino_sz = sizeof(unsigned long);
  unsigned int slen = (21 * sizeof(char));
  unsigned int rec_size = slen + ino_sz;
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
      printf("func : %s file ino: %lu\n", (char *)buf, *(unsigned long *)(buf + (slen)));
    }
  close(sourceFile);
  return;

}