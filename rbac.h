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
	struct file *fout = NULL;
	unsigned int ruid_sz = sizeof(int);
	unsigned int slen = MAX_NAME_LENGTH * sizeof(char);
	unsigned int buflen = ruid_sz+slen; 
	char *buf = kmalloc(buflen, GFP_KERNEL);
	mm_segment_t oldfs;


	printk(KERN_DEBUG "*************IN %s\n",__func__);
	printk(KERN_DEBUG "For ruid : %d\n",ruid);
  	
    oldfs=get_fs();
    set_fs(KERNEL_DS);
	
	fout=filp_open("/etc/rbac/users", O_RDONLY, (mode_t) 00755);
    
    if(!fout||IS_ERR(fout))
    {
        printk("Error Opening the File : %d\n", (int)PTR_ERR(fout));
        goto exit_err;
    }

    while ((rbytes=vfs_read(fout, buf, buflen, &fout->f_pos)) > 0 ) {
    	int user_ruid;
    	memcpy((void *) &user_ruid, buf, ruid_sz);
    	
    	if(ruid == user_ruid) {
    		flag = 1;
    		memcpy(role, (buf + (ruid_sz)), slen);
    		printk(KERN_DEBUG "Role Found : %s\n",role);
    		break;
    	}
    }

    exit_err:
    if(fout != NULL)
    	filp_close(fout, NULL);
    set_fs(oldfs);
    kfree(buf);

    if(flag == 0) {
    	role = NULL;
    	return -1;
    }
    else return 0;

}
int user_permitted (char * role, const char * fun_name, struct dentry *dentry, int par_check) {
	int flag = 0, rbytes;
	struct file *fout = NULL;
	unsigned int ino_sz = sizeof(unsigned long);
	unsigned int slen = MAX_NAME_LENGTH * sizeof(char);
	unsigned int buflen = ino_sz + slen; 
	char *buf = kmalloc(buflen, GFP_KERNEL);
	mm_segment_t oldfs;
	char role_file[50];
	char *fname = NULL;
	const char *file_name = dentry->d_name.name;
	unsigned long ino_no = 0;


	strcpy(role_file, "/etc/rbac/roles/");
	strcat(role_file, role);
	oldfs=get_fs();
    set_fs(KERNEL_DS);

	printk(KERN_DEBUG "*************IN %s\n",__func__);

	if(dentry->d_inode != NULL) {
		ino_no = (unsigned long) dentry->d_inode->i_ino;
	}
	else if(par_check == 1) {
		struct dentry* parent = dentry->d_parent;
		struct inode* p_inode = parent->d_inode;
		ino_no = (unsigned long) p_inode->i_ino;
		printk(KERN_DEBUG"File: %s Doesnt Exists \n", file_name);
		printk(KERN_DEBUG"But Parent: %s Exits with inode:%lu\n", \
			parent->d_name.name, ino_no );
	}

	printk(KERN_DEBUG "For role : %s\n",role);
    printk(KERN_DEBUG "Given func : %s file : %s \n",fun_name, file_name);
    

	fout=filp_open(role_file, O_RDONLY, (mode_t) 00755);
    
    if(!fout||IS_ERR(fout))
    {
        printk("Error Opening the File : %d\n", (int)PTR_ERR(fout));
        goto exit_err;
    }

    while ((rbytes=vfs_read(fout, buf, buflen, &fout->f_pos)) > 0 ) {
    		printk(KERN_DEBUG "Buffer func : %s file ino: %lu \n",(char *)buf, *(unsigned long *)(buf+slen));
    	if(!strcmp(fun_name, (char *)buf) && (ino_no == *(unsigned long*)(buf+slen))) {
    		printk(KERN_DEBUG "Rule found! func : %s file ino: %lu \n",fun_name, ino_no);
    		flag = 1;
    		break;
    	}
    }

    exit_err:
    if(fout != NULL)
    	filp_close(fout, NULL);
    set_fs(oldfs);
    kfree(buf);

    if(flag == 0)
    	return -1;
    else 
    	return 0;

}

int IS_IN_DOMAIN(struct dentry *dentry) {

	int flag = 0, rbytes;
	struct file *fout = NULL;
	unsigned int  ino_sz = sizeof(unsigned long);
	unsigned int slen = MAX_NAME_LENGTH * sizeof(char);
	unsigned int buflen = ino_sz + slen; 
	char *buf = kmalloc(buflen, GFP_KERNEL);
	mm_segment_t oldfs;
	struct dentry* tmp_dentry = dentry;
	
	printk(KERN_DEBUG "*************IN %s\n",__func__);
  	oldfs=get_fs();
    set_fs(KERNEL_DS);
  	
  	if(IS_ROOT(tmp_dentry)) {
  		goto exit_err;
  	}
  	else {
  		while(!IS_ROOT(tmp_dentry->d_parent)) {
  			tmp_dentry = dentry->d_parent;
  		}
  	}

   
	
	fout=filp_open("/etc/rbac/dir_domains", O_RDONLY, (mode_t) 00755);
    
    if(!fout||IS_ERR(fout))
    {
        printk("Error Opening the File : %d\n", (int)PTR_ERR(fout));
        goto exit_err;
    }

    while ((rbytes=vfs_read(fout, buf, buflen, &fout->f_pos)) > 0 ) {
    	
    	if(tmp_dentry->d_inode->i_ino ==  *(unsigned long *) buf) {
    		flag = 1;
    		printk(KERN_DEBUG "Dir domain Found! for : %s\n",(char *)(buf+ino_sz));
    		break;
    	}
    }

    exit_err:
    if(fout != NULL)
    	filp_close(fout, NULL);
    set_fs(oldfs);
    kfree(buf);

    if(flag == 0) {
    	return 0;
    }
    else return 1;
}