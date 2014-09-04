#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<sys/stat.h> //mode_t
#include<fcntl.h>
#include<string.h>

#define BUF_SIZE 4096

int add_user_to_role(int ruid, char *role);
void read_user_to_role();

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
   		 			char * role = argv[2];
   		 			int func = (int) strtol(argv[3] ,NULL , 10);
   		 			char *fname = argv[4];
   		 			printf("Role : %s Function : %d File Name : %s\n",role, func, fname);
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
         case 5 : printf("Delete a Rule\n"); 
         			if(argc !=2)
   		 				disp_error();

         			read_user_to_role();
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

    sourceFile = open("/tmp/users", O_RDWR|O_CREAT|O_APPEND);
    
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
    	return -1;
    }
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

    sourceFile = open("/tmp/users", O_RDONLY);
    
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

}

int add_rule_to_role(char *role, int func, char *file_name) 
{	
	int sourceFile;
	unsigned int func_sz = sizeof(int);
	unsigned int slen = (21 * sizeof(char));
	unsigned int rec_size = func_sz + slen;
    void* buf = (void *)malloc(rec_size);
    int wrBytes = 0;

    sourceFile = open(strcat("/tmp/roles/", role), O_RDWR|O_CREAT|O_APPEND);
    
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        return -1;
    }
    printf("Int func size %d\n", sizeof(int));
    memcpy(buf , (void *) &func, func_sz);
    memcpy(buf + func_sz , role, strlen(file_name)+1);
    printf("role : %s func : %d file : %s\n", role, *(int*)buf, (char *)(buf + (func_sz)));
    wrBytes = write(sourceFile, buf, rec_size);
    if ( wrBytes != rec_size){
    	printf("Partial Write Error\n");
    	return -1;
    }
    return 0;

}