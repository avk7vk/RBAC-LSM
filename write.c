#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>  
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BUF_SIZE 4096
#define MAX_ITR 100

long getTimeInterval(struct timeval , struct timeval) ;

int main(int argc, char **argv)
{
    int sourceFile;
    int destFile;
    int counter = 0;
    char* buf = (char *)malloc(sizeof(char) * BUF_SIZE);
    int rdBytes = 0, wrBytes = 0;
    struct timeval tv, tv1;
    long totTime = 0, totWrite = 0;
    double speed = 0;
     sourceFile = open("/tmp/", O_RDONLY);
    if(sourceFile < 0)
    {
        printf("Error opening source file %d\n", sourceFile);
        return 2;
    }
    destFile = open("mnt_ubifs/file", O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);
 
    if(destFile < 0)
    {
        printf("Error opening Dest file %d\n", destFile);
        return 3;
    }

    while(rdBytes = read(sourceFile, buf, BUF_SIZE ))
    {
        if(rdBytes < 0) {
            printf("Error Reading Data %d\n", rdBytes);
            return 3;   
        }

    	gettimeofday(&tv, NULL);
            wrBytes = write(destFile, buf, rdBytes);
    	gettimeofday(&tv1, NULL);
        totTime += getTimeInterval(tv, tv1);
     //   printf("TIme is %ld\n", totTime);
    	//printf("Written bytes %d\n", wrBytes);
    	totWrite += wrBytes;
    	if ( wrBytes != rdBytes){
    		printf("Partial Write Error\n");
    		return 4;
    	}
        counter++;
        if(counter >= MAX_ITR)
            break;
    }
    
    gettimeofday(&tv, NULL);
    fsync(destFile);
    gettimeofday(&tv1, NULL);
    
    totTime += getTimeInterval(tv, tv1);
    printf("TOtal Time is %ld and write is %ld KB\n", totTime, totWrite/1024);
    speed = ((double) totWrite * 1000 * 1000)/((double)totTime * 1024 * 1024);
   
    printf("Total Write Time is %ld ms\n", totTime);
    printf("Write Speed is %lf MB/s\n", speed);
    close(sourceFile);
    close(destFile);
    
    /* Write to a location */
    destFile = open("mnt_ubifs/file", O_RDWR, S_IRUSR|S_IWUSR);
    if(destFile < 0)
    {
        printf("Error opening Dest file %d\n", destFile);
        return 3;
    }
    
    counter = 20;
    while(counter > 0)
    {

            wrBytes = write(destFile, buf, BUF_SIZE);
     //   printf("TIme is %ld\n", totTime);
        printf("Written bytes %d\n", wrBytes);
        counter--;
    }
    
    fsync(destFile);
    close(destFile);

    return 0;
}

long getTimeInterval(struct timeval start, struct timeval end) 
{
    long seconds = end.tv_sec - start.tv_sec;
    long micro_seconds = end.tv_usec - start.tv_usec;
    //printf("Difference is %ld\n", micro_seconds);
    if (micro_seconds < 0)
    {
        seconds -= 1;
    }

    return (seconds * 1000000) + abs(micro_seconds);
}
