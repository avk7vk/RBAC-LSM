#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<sys/stat.h> //mode_t
#include<fcntl.h>
#define __NR_xconcat	349	/* our private syscall number */
   struct idata{
         const  char *outfile;
         const  char ** infiles;
         unsigned  int infile_count;
         int oflags;
          mode_t mode;
         unsigned int flags;
        }params;

int main(int argc, char *argv[])
{
	int rc,i,c;/*
        params.oflags=NULL;
        params.flags=NULL;
        params.mode=NULL;
        params.outfile=NULL;
        params.infiles=NULL;
        params.infile_count=NULL;*/
        params=(struct idata){0};
 	 while((c=getopt(argc,argv,"acteANPm:h"))!=-1){
          switch(c){
           	 case 'a':params.oflags=params.oflags|O_APPEND;
          	   	 break;
           	 case 'c':params.oflags=params.oflags|O_CREAT;
             	   	 break; 
  		 case 't':params.oflags=params.oflags|O_TRUNC;
           		 break;
		 case 'e':params.oflags=params.oflags|O_EXCL;
           		 break;
		 case 'A':params.flags=1;
          	 	 break;
   		 case 'N':params.flags=2;
           		 break; 
  		 case 'P':params.flags=3;
          		 break;   
   		 case 'm':params.mode=strtol(optarg,NULL,8);
           		 break;   
  		 case 'h':printf("Welcome to help\n");
                         exit(1);
           		 break;   
                 default:printf("Invalid Option\n");
  	 }
       }
        printf("argc=%d,output=%s\n",argc,argv[optind]);
        c=optind;
        params.infiles= malloc(sizeof(char*)*(argc-c));
        params.outfile=argv[c++];
        for(i=c;i<argc;i++){
       	    printf("%s\n",argv[i]);	
            params.infiles[i-c]=argv[i];
        }
        params.infile_count=argc-c;
        
  	rc = syscall(__NR_xconcat,(void *)&params,sizeof(params));
	if (rc >=0)
	       printf("syscall returned %d\n", rc);
	else
        {
		printf("syscall returned %d (errno=%d)\n", rc, errno);
                perror("Error : ");
        }
	exit(rc);
}
