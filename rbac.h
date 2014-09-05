#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>

enum {

	INODE_ALLOC_SECURITY,
	INODE_FREE_SECURITY,
	INODE_INIT_SECURITY,
	INODE_CREATE,
	INODE_LINK,
	INODE_UNLINK,
	INODE_SYMLINK,
	INODE_MKDIR,
	INODE_RMDIR,
	INODE_MKNOD,
	INODE_RENAME,
	INODE_READLINK,
	INODE_FOLLOW_LINK,
	INODE_PERMISSION,
	INODE_SETATTR,
	INODE_GETATTR,
	INODE_SETXATTR,
	INODE_POST_SETXATTR,
	INODE_GETXATTR,
	INODE_LISTXATTR,
	INODE_REMOVEXATTR,
	INODE_GETSECURITY,
	INODE_SETSECURITY,
	INODE_LISTSECURITY,
	INODE_GETSECID
};
#define MAX_NAME_LENGTH 21

int read_role(int ruid, char * role) {

	int flag = 0, rbytes;
	struct file *fout;
	unsigned int ruid_sz = sizeof(int);
	unsigned int slen = MAX_NAME_LENGTH * sizeof(char);
	unsigned int buflen = ruid_sz+slen; 
	char *buf = kmalloc(buflen, GFP_KERNEL);
	mm_segment_t oldfs;


    oldfs=get_fs();
    set_fs(KERNEL_DS);
	fout=filp_open("/tmp/users", O_RDONLY, 0);
    
    if(!fout||IS_ERR(fout))
    {
        printk("Error Opening the File\n");
        return PTR_ERR(fout);
    }

    while ((rbytes=vfs_read(fout, buf, buflen, &fout->f_pos)) > 0 ) {
    	int user_ruid;
    	memcpy((void *) &user_ruid, buf, ruid_sz);
    	
    	if(ruid == user_ruid) {
    		flag == 1;
    		memcpy(role, (buf + (ruid_sz)), slen);
    		break;
    	}
    }


    set_fs(oldfs);
    kfree(buf);

    if(flag == 0) {
    	role == NULL;
    	return -1;
    }
    else return 0;

}
int user_permitted (char * role, char * fun_name, char * file_name) {
	int flag = 0, rbytes;
	struct file *fout;
	unsigned int slen = MAX_NAME_LENGTH * sizeof(char);
	unsigned int buflen = 2 * slen; 
	char *buf = kmalloc(buflen, GFP_KERNEL);
	mm_segment_t oldfs;


    oldfs=get_fs();
    set_fs(KERNEL_DS);
	fout=filp_open(strcat("/tmp/roles/", role), O_RDONLY, 0);
    
    if(!fout||IS_ERR(fout))
    {
        printk("Error Opening the File\n");
        return PTR_ERR(fout);
    }

    while ((rbytes=vfs_read(fout, buf, buflen, &fout->f_pos)) > 0 ) {
    	
    	if(!strcmp(fun_name, (char *)buf) && !strcmp(fun_name, (char *)(buf+slen)) {
    		flag == 1;
    		break;
    	}
    }

    set_fs(oldfs);
    kfree(buf);

    if(flag == 0)
    	return -1;
    else 
    	return 0;

}
