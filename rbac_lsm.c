/*
 * SBRBAC Linux Security Module
 *
 * Author: Vamsi Krishna Atluri <vamsikrishna.atluri@stonybrook.edu>
 * ID 	 : 109597320
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/security.h>
#include <linux/sysctl.h>
#include <linux/xattr.h>
#include <linux/pagemap.h>
#include <linux/mount.h>
#include <linux/stat.h>
#include <linux/kd.h>
#include <asm/ioctls.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/pipe_fs_i.h>
#include <net/cipso_ipv4.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/audit.h>
#include <linux/magic.h>
#include <linux/dcache.h>
#include <linux/personality.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/binfmts.h>
#include <linux/string.h>
#include <linux/fs.h>

#include "rbac.h"

/*
 * Inode hooks
 */

/**
 * rbac_inode_alloc_security - allocate an inode blob
 * @inode: the inode in need of a blob
 *
 * Returns 0 if it gets a blob, -ENOMEM otherwise
 */
static int rbac_inode_alloc_security(struct inode *inode)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return 0;
}

/**
 * rbac_inode_free_security - free an inode blob
 * @inode: the inode with a blob
 *
 * Clears the blob pointer in inode
 */
static void rbac_inode_free_security(struct inode *inode)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
}

/**
 * rbac_inode_init_security - copy out the rbac from an inode
 * @inode: the inode
 * @dir: unused
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * Returns 0 if it all works out, -ENOMEM if there's no memory
 */
static int rbac_inode_init_security(struct inode *inode, struct inode *dir,
				     const struct qstr *qstr, const char **name,
				     void **value, size_t *len)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return 0;
}
/**
 * rbac_inode_create
 * Returns 0 if access is permitted, an error code otherwise
 */
static int rbac_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	const char* name = dentry->d_name.name;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	int ruid = (int)rcred->uid.val;

	printk(KERN_DEBUG "***************RBAC: %s ************\n",__func__);
	printk(KERN_DEBUG "File Name : %s\n", name);
	printk(KERN_DEBUG "Process Real creds ruid: %d \t rgid: %d\n",(int)rcred->uid.val, (int)rcred->gid.val);
	//if(!strcmp(name,"/tmp/file_avk") || !strcmp(name,"file_avk")) {
		if(((int)rcred->uid.val) != 0) {
			char role[21];
			if(!IS_IN_DOMAIN(dentry)) {
				printk(KERN_DEBUG"FIle is not in Domain %s\n", name);
				goto exit_norm;
			}
			if(!read_role(ruid, role)) {
				// Important keeping it to permit all except option

				if(!user_permitted (role, __func__, dentry, 1)) {
					goto exit_norm;
				}
				else goto exit_err;
			}
			else goto exit_err;
			
		}
		
	exit_norm:
	return 0;

	exit_err:
	printk(KERN_DEBUG "RBAC : Access Denied for File Name : %s\n", name);
	return -EACCES;
}
/**
 * rbac_inode_link - rbac check on link
 * @old_dentry: the existing object
 * @dir: unused
 * @new_dentry: the new object
 *
 * Returns 0 if access is permitted, an error code otherwise
 */
static int rbac_inode_link(struct dentry *old_dentry, struct inode *dir,
			    struct dentry *new_dentry)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return 0;
}

/**
 * rbac_inode_unlink - rbac check on inode deletion
 * @dir: containing directory object
 * @dentry: file to unlink
 *
 * Returns 0 if current can write the containing directory
 * and the object, error code otherwise
 */
static int rbac_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	
	const char* name = dentry->d_name.name;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	int ruid = (int)rcred->uid.val;

	printk(KERN_DEBUG "***************RBAC: %s ************\n",__func__);
	printk(KERN_DEBUG "File Name : %s\n", name);
	printk(KERN_DEBUG "Process Real creds ruid: %d \t rgid: %d\n",(int)rcred->uid.val, (int)rcred->gid.val);
	//if(!strcmp(name,"/tmp/file_avk") || !strcmp(name,"file_avk")) {
		if(((int)rcred->uid.val) != 0) {
			char role[21];
			if(!IS_IN_DOMAIN(dentry)) {
				printk(KERN_DEBUG"FIle is not in Domain %s\n", name);
				goto exit_norm;
			}
			if(!read_role(ruid, role)) {
				// Important keeping it to permit all except option

				if(!user_permitted (role, __func__, dentry, 0)) {
					goto exit_norm;
				}
				else goto exit_err;
			}
			else goto exit_err;
			
		}
		
	exit_norm:
	return 0;

	exit_err:
	printk(KERN_DEBUG "RBAC : Access Denied for File Name : %s\n", name);
	return -EACCES;
}
/**
 * rbac_inode_symlink
 * Returns 0 if current can write the containing directory
 * and the object, error code otherwise
 */
static int rbac_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	return 0;
}
/**
 * rbac_inode_mkdir
 * Returns 0 if current can write the containing directory
 * and the object, error code otherwise
 */
static int rbac_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	const char* name = dentry->d_name.name;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	int ruid = (int)rcred->uid.val;

	printk(KERN_DEBUG "***************RBAC: %s ************\n",__func__);
	printk(KERN_DEBUG "Dir Name : %s\n", name);
	printk(KERN_DEBUG "Process Real creds ruid: %d \t rgid: %d\n",(int)rcred->uid.val, (int)rcred->gid.val);
	//if(!strcmp(name,"/tmp/file_avk") || !strcmp(name,"file_avk")) {
		if(((int)rcred->uid.val) != 0) {
			char role[21];
			if(!IS_IN_DOMAIN(dentry)) {
				printk(KERN_DEBUG"Dir is not in Domain %s\n", name);
				goto exit_norm;
			}
			if(!read_role(ruid, role)) {
				// Important keeping it to permit all except option

				if(!user_permitted (role, __func__, dentry, 1)) {
					goto exit_norm;
				}
				else goto exit_err;
			}
			else goto exit_err;
			
		}
		
	exit_norm:
	return 0;

	exit_err:
	printk(KERN_DEBUG "RBAC : Access Denied for File Name : %s\n", name);
	return -EACCES;
}
/**
 * rbac_inode_rmdir - rbac check on directory deletion
 * @dir: containing directory object
 * @dentry: directory to unlink
 *
 * Returns 0 if current can write the containing directory
 * and the directory, error code otherwise
 */
static int rbac_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	const char* name = dentry->d_name.name;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	int ruid = (int)rcred->uid.val;

	printk(KERN_DEBUG "***************RBAC: %s ************\n",__func__);
	printk(KERN_DEBUG "Dir Name : %s\n", name);
	printk(KERN_DEBUG "Process Real creds ruid: %d \t rgid: %d\n",(int)rcred->uid.val, (int)rcred->gid.val);
	//if(!strcmp(name,"/tmp/file_avk") || !strcmp(name,"file_avk")) {
		if(((int)rcred->uid.val) != 0) {
			char role[21];
			if(!IS_IN_DOMAIN(dentry)) {
				printk(KERN_DEBUG"Dir is not in Domain %s\n", name);
				goto exit_norm;
			}
			if(!read_role(ruid, role)) {
				// Important keeping it to permit all except option

				if(!user_permitted (role, __func__, dentry, 0)) {
					goto exit_norm;
				}
				else goto exit_err;
			}
			else goto exit_err;
			
		}
		
	exit_norm:
	return 0;

	exit_err:
	printk(KERN_DEBUG "RBAC : Access Denied for File Name : %s\n", name);
	return -EACCES;
}
/**
 * rbac_inode_mknod
 * Returns 0 if current can write the containing directory
 * and the object, error code otherwise
 */
static int rbac_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	return 0;
}
/**
 * rbac_inode_rename - rbac check on rename
 * @old_inode: the old directory
 * @old_dentry: unused
 * @new_inode: the new directory
 * @new_dentry: unused
 *
 * unlink permission are checked in @old_dentry and create permission are checked in @new_dentry
 *
 * Returns 0 if access is permitted, an error code otherwise
 */
static int rbac_inode_rename(struct inode *old_inode,
			      struct dentry *old_dentry,
			      struct inode *new_inode,
			      struct dentry *new_dentry)
{
	const char* name = old_dentry->d_name.name;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	int ruid = (int)rcred->uid.val;

	printk(KERN_DEBUG "***************RBAC: %s ************\n",__func__);
	printk(KERN_DEBUG "File Name : %s\n", name);
	printk(KERN_DEBUG "Process Real creds ruid: %d \t rgid: %d\n",(int)rcred->uid.val, (int)rcred->gid.val);
	//if(!strcmp(name,"/tmp/file_avk") || !strcmp(name,"file_avk")) {
		if(((int)rcred->uid.val) != 0) {
			char role[21];
			if(!IS_IN_DOMAIN(old_dentry) && !IS_IN_DOMAIN(new_dentry)) {
				printk(KERN_DEBUG"Dirs are not in Domain %s\n", name);
				goto exit_norm;
			}
			if(!read_role(ruid, role)) {
				// Important keeping it to permit all except option

				if(!user_permitted (role, "rbac_inode_unlink", old_dentry, 0) && 
					!user_permitted (role, "rbac_inode_create", new_dentry, 1)) {
					goto exit_norm;
				}
				else goto exit_err;
			}
			else goto exit_err;
			
		}
		
	exit_norm:
	return 0;

	exit_err:
	printk(KERN_DEBUG "RBAC : Access Denied for File Name : %s\n", name);
	return -EACCES;
}
/**
 * rbac_inode_readlink
 * Returns 0 if current can write the containing directory
 * and the object, error code otherwise
 */
static int rbac_inode_readlink(struct dentry *dentry)
{
	return 0;
}
/**
 * rbac_inode_follow_link
 * Returns 0 if current can write the containing directory
 * and the object, error code otherwise
 */
static int rbac_inode_follow_link(struct dentry *dentry, struct nameidata *nameidata)
{
	return 0;
}
/**
 * rbac_inode_permission - rbac version of permission()
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important rbac hook.
 *
 * Returns 0 if access is permitted, -EACCES otherwise
 */
static int rbac_inode_permission(struct inode *inode, int mask)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return 0;
}

/**
 * rbac_inode_setattr - rbac check for setting attributes
 * @dentry: the object
 * @iattr: for the force flag
 *
 * Returns 0 if access is permitted, an error code otherwise
 */
static int rbac_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	const char* name = dentry->d_name.name;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	int ruid = (int)rcred->uid.val;

	printk(KERN_DEBUG "***************RBAC: %s ************\n",__func__);
	printk(KERN_DEBUG "Dir Name : %s\n", name);
	printk(KERN_DEBUG "Process Real creds ruid: %d \t rgid: %d\n",(int)rcred->uid.val, (int)rcred->gid.val);
	//if(!strcmp(name,"/tmp/file_avk") || !strcmp(name,"file_avk")) {
		if(((int)rcred->uid.val) != 0) {
			char role[21];
			if(!IS_IN_DOMAIN(dentry)) {
				printk(KERN_DEBUG"Dir is not in Domain %s\n", name);
				goto exit_norm;
			}
			if(!read_role(ruid, role)) {
				// Important keeping it to permit all except option

				if(!user_permitted (role, __func__, dentry, 0)) {
					goto exit_norm;
				}
				else goto exit_err;
			}
			else goto exit_err;
			
		}
		
	exit_norm:
	return 0;

	exit_err:
	printk(KERN_DEBUG "RBAC : Access Denied for File Name : %s\n", name);
	return -EACCES;
}

/**
 * rbac_inode_getattr - rbac check for getting attributes
 * @mnt: unused
 * @dentry: the object
 *
 * Returns 0 if access is permitted, an error code otherwise
 */
static int rbac_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	const char* name = dentry->d_name.name;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	int ruid = (int)rcred->uid.val;

	printk(KERN_DEBUG "***************RBAC: %s ************\n",__func__);
	printk(KERN_DEBUG "Dir Name : %s\n", name);
	printk(KERN_DEBUG "Process Real creds ruid: %d \t rgid: %d\n",(int)rcred->uid.val, (int)rcred->gid.val);
	//if(!strcmp(name,"/tmp/file_avk") || !strcmp(name,"file_avk")) {
		if(((int)rcred->uid.val) != 0) {
			char role[21];
			if(!IS_IN_DOMAIN(dentry)) {
				printk(KERN_DEBUG"Dir is not in Domain %s\n", name);
				goto exit_norm;
			}
			if(!read_role(ruid, role)) {
				// Important keeping it to permit all except option

				if(!user_permitted (role, __func__, dentry, 0)) {
					goto exit_norm;
				}
				else goto exit_err;
			}
			else goto exit_err;
			
		}
		
	exit_norm:
	return 0;

	exit_err:
	printk(KERN_DEBUG "RBAC : Access Denied for File Name : %s\n", name);
	return -EACCES;
}

/**
 * rbac_inode_setxattr - rbac check for setting xattrs
 * @dentry: the object
 * @name: name of the attribute
 * @value: unused
 * @size: unused
 * @flags: unused
 *
 * This protects the rbac attribute explicitly.
 *
 * Returns 0 if access is permitted, an error code otherwise
 */
static int rbac_inode_setxattr(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return 0;
}

/**
 * rbac_inode_post_setxattr - Apply the rbac update approved above
 * @dentry: object
 * @name: attribute name
 * @value: attribute value
 * @size: attribute size
 * @flags: unused
 *
 * Set the pointer in the inode blob to the entry found
 * in the master label list.
 */
static void rbac_inode_post_setxattr(struct dentry *dentry, const char *name,
				      const void *value, size_t size, int flags)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return;
}

/**
 * rbac_inode_getxattr - rbac check on getxattr
 * @dentry: the object
 * @name: unused
 *
 * Returns 0 if access is permitted, an error code otherwise
 */
static int rbac_inode_getxattr(struct dentry *dentry, const char *name)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return 0;
}
/**
 * rbac_inode_listxattr
 * Returns 0 if access is permitted, an error code otherwise
 */
static int rbac_inode_listxattr(struct dentry *dentry)
{

	return 0;
}
/**
 * rbac_inode_removexattr - rbac check on removexattr
 * @dentry: the object
 * @name: name of the attribute
 *
 * Removing the rbac attribute requires CAP_MAC_ADMIN
 *
 * Returns 0 if access is permitted, an error code otherwise
 */
static int rbac_inode_removexattr(struct dentry *dentry, const char *name)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return 0;
}

/**
 * rbac_inode_getsecurity - get rbac xattrs
 * @inode: the object
 * @name: attribute name
 * @buffer: where to put the result
 * @alloc: unused
 *
 * Returns the size of the attribute or an error code
 */
static int rbac_inode_getsecurity(const struct inode *inode,
				   const char *name, void **buffer,
				   bool alloc)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return 0;
}
/**
 * rbac_inode_setsecurity 
 * Returns the size of the attribute or an error code
 */
static int rbac_inode_setsecurity(struct inode *inode, const char *name,
				     const void *value, size_t size, int flags)
{
	return 0;
}
/**
 * rbac_inode_listsecurity - list the rbac attributes
 * @inode: the object
 * @buffer: where they go
 * @buffer_size: size of buffer
 *
 * Returns 0 on success, -EINVAL otherwise
 */
static int rbac_inode_listsecurity(struct inode *inode, char *buffer,
				    size_t buffer_size)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
	return 0;
}

/**
 * rbac_inode_getsecid - Extract inode's security id
 * @inode: inode to extract the info from
 * @secid: where result will be saved
 */
static void rbac_inode_getsecid(const struct inode *inode, u32 *secid)
{
	//printk(KERN_DEBUG "rbac: %s\n",__func__);
}

static struct security_operations rbac_ops = {
	.name =			"rbac",

	.inode_alloc_security = 	rbac_inode_alloc_security,
	.inode_free_security = 		rbac_inode_free_security,
	.inode_init_security = 		rbac_inode_init_security,
	.inode_create =			rbac_inode_create, //implemented
	.inode_link = 			rbac_inode_link,
	.inode_unlink = 		rbac_inode_unlink, //implemented
	.inode_symlink =		rbac_inode_symlink,
	.inode_mkdir =			rbac_inode_mkdir, //implemented
	.inode_rmdir = 			rbac_inode_rmdir, //implemented
	.inode_mknod =			rbac_inode_mknod,
	.inode_rename = 		rbac_inode_rename, //implemented
	.inode_readlink =		rbac_inode_readlink,
	.inode_follow_link =		rbac_inode_follow_link,
	.inode_permission = 		rbac_inode_permission,
	.inode_setattr = 		rbac_inode_setattr, //implemented
	.inode_getattr = 		rbac_inode_getattr, //implemented
	.inode_setxattr = 		rbac_inode_setxattr,
	.inode_post_setxattr = 		rbac_inode_post_setxattr,
	.inode_getxattr = 		rbac_inode_getxattr,
	.inode_listxattr =		rbac_inode_listxattr,
	.inode_removexattr = 		rbac_inode_removexattr,
	.inode_getsecurity = 		rbac_inode_getsecurity,
	.inode_setsecurity =		rbac_inode_setsecurity,
	.inode_listsecurity = 		rbac_inode_listsecurity,
	.inode_getsecid =		rbac_inode_getsecid
};

static __init int rbac_init(void)
{
	if (!security_module_enable(&rbac_ops))
		return 0;

	printk(KERN_INFO "rbac: becoming mindful.\n");

	if (register_security(&rbac_ops))
		panic("rbac: kernel registration failed.\n");

	return 0;
}

security_initcall(rbac_init);
