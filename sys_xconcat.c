#include <linux/linkage.h>
#include<linux/err.h>
#include<linux/fs.h>
#include <linux/moduleloader.h>
#include<linux/uaccess.h>
#include<linux/slab.h>
#include<linux/compiler.h> //__user
#include<linux/types.h>// mode_t
#include<asm-generic/errno-base.h>
#include<asm-generic/errno.h>

asmlinkage extern long (*sysptr)(void *arg,int argslen);
struct idata{
__user const char *outfile;
__user const char **infiles;
unsigned int infile_count;
unsigned int oflags;
mode_t mode;
unsigned int flags;
}; 


asmlinkage long xconcat(void *arg,int argslen)
{
  struct kstat sb; 
  struct idata *test=(struct idata *) arg;
 char *buf=kmalloc(4096,GFP_KERNEL);
  mm_segment_t oldfs;
  const  int n=test->infile_count;
  struct file *filp[n],*fout;
  int total_in_size=0;
  int rbytes=0,wbytes=0,totwbytes=0,file_rbytes=0,trbytes=0;
  int i=0,stat_var;
  unsigned long LEN=4096;
  int dflag=0;
  //   i=i;wbytes=wbytes;rbytes=rbytes;n=n;oldfs=oldfs;filp=0;
       buf=kmalloc(LEN,GFP_KERNEL);
       //Arguments length check
       printk("Args length=%d",argslen);
        if(sizeof(struct idata)!=argslen){
	   return -EINVAL;
        }
      //Null & Missing Args check
       if(test->outfile==0||test->infiles==0||test->infile_count==0)
       {
     	   return -EINVAL;
       }
          if(test->oflags==0) test->oflags=O_CREAT|O_RDWR|O_APPEND;
          else test->oflags=test->oflags|O_RDWR;
	  if(test->mode==0) test->mode=00755;
          if(test->flags==0) test->flags=0;
 
      //Invalid Flags
        if(test->infile_count<1)
        {
		return -EINVAL;//EINVAL
        }
      //Bad pointer Check
        if(!access_ok(VERIFY_WRITE,test->outfile,1)|!access_ok(VERIFY_WRITE,test->infiles,1)){
           printk("BAd pointer 1\n");
             return -EFAULT;
         } 
         for(i=0;i<n;i++){
            if(!access_ok(VERIFY_WRITE,test->infiles[i],1)){
              printk("Bad pointer 2\n");
                return -EFAULT;  
             }
         }
      //Concatenation Process
      fout=filp_open(test->outfile,test->oflags,test->mode);
       if(!fout||IS_ERR(fout))
       {
 		//check if oflags,mode are invalid based on the Errno set
             printk("FIle Creation Error\n");
             return PTR_ERR(fout);
       } 
       

     printk("successfully opened outfile");
      for(i=0; i<n;i++)   
      {   filp[i]=filp_open(test->infiles[i],O_RDWR,0);
         if(!filp[i] || IS_ERR(filp[i]))
         { 
           printk("Error in file opening\n");
           return PTR_ERR(filp[i]);
         }         
         if(!filp[i]->f_op->read)
         {
            printk("Read Error\n");
             return -1;
         }
         stat_var= vfs_stat(test->infiles[i],&sb);
         total_in_size+=sb.size;
         printk("Input file%d",total_in_size);
       }
        printk("Test");
       for(i=0;i<n;i++){
      	  rbytes=0;wbytes=0,file_rbytes=0;
          do{
                 
		 printk("\nEntering DO LOOP\n");
         	  filp[i]->f_pos=file_rbytes;
        	  fout->f_pos=totwbytes;
          	  printk("\nF_POS for Append is %d\n",(int)fout->f_pos);
		  oldfs=get_fs();
           	  set_fs(KERNEL_DS);
           	  rbytes=vfs_read(filp[i],buf,LEN,&filp[i]->f_pos);
           	  file_rbytes+=rbytes;
 	  	  printk("\nFmode%d",fout->f_mode);
           	  wbytes=vfs_write(fout,buf,rbytes,&fout->f_pos);
           	  printk("\nfile_rbytes= %d , wbytes= %d",file_rbytes,wbytes);
                  if(wbytes<0){
                    if(test->flags==2)
		       return i;
		    if(test->flags==3)
		       return totwbytes*100/total_in_size;   
                    return totwbytes;
                  }
                  set_fs(oldfs);
                  if(dflag==0){
		  wbytes=95;//debugging
                  dflag=1;
                  }
			 if(wbytes<rbytes)//Rewrite again
			 {
			   printk("\nRewrite Attempt wbytes=%d rbytes=%d",wbytes,rbytes);
			   file_rbytes-=rbytes;
			   continue;

			  }
			  totwbytes+=wbytes;                 
		   }while(rbytes>0); 
		   trbytes+=file_rbytes;
		   filp_close(filp[i],NULL);
	       } 
	      filp_close(fout,NULL); 
	      kfree(buf);
	     if(test->flags==2)
       return n;
     else if(test->flags==3)
       return 100*(totwbytes/trbytes);
     else
      return totwbytes; 
}

static int __init init_sys_xconcat(void)
{
	printk("installed new sys_xconcat module\n");
	if (sysptr == NULL)
		sysptr = xconcat;
	return 0;
}
static void  __exit exit_sys_xconcat(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xconcat module\n");
}
module_init(init_sys_xconcat);
module_exit(exit_sys_xconcat);
MODULE_LICENSE("GPL");
