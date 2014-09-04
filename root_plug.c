/*
 * Root Plug sample LSM module
 *
 * Written for Linux Journal article.
 *
 * Copyright (C) 2002 Greg Kroah-Hartman <greg@kroah.com>
 *
 * Based on the security/dummy.c module.
 *
 * Prevents any programs running with egid == 0 if a specific USB device is not
 * present in the system.  Yes, it can be gotten around, but is a nice starting
 * point for people to play with, and learn the LSM interface.
 *
 * If you want to turn this into something with a semblance of security, you
 * need to hook the task_* functions also.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2 of the License.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/usb.h>

/* flag to keep track of how we were registered */
static int secondary;

static int rootplug_ptrace (struct task_struct *parent,
			    struct task_struct *child)
{
	return 0;
}

static int rootplug_capget (struct task_struct *target,
			    kernel_cap_t *effective,
			    kernel_cap_t *inheritable,
			    kernel_cap_t *permitted)
{
	return 0;
}

static int rootplug_capset_check (struct task_struct *target,
				  kernel_cap_t *effective,
				  kernel_cap_t *inheritable,
				  kernel_cap_t *permitted)
{
	return 0;
}

static void rootplug_capset_set (struct task_struct *target,
				 kernel_cap_t *effective,
				 kernel_cap_t *inheritable,
				 kernel_cap_t *permitted)
{
	return;
}

static int rootplug_acct (struct file *file)
{
	return 0;
}

static int rootplug_capable (struct task_struct *tsk, int cap)
{
	if (cap_is_fs_cap (cap) ? tsk->fsuid == 0 : tsk->euid == 0)
		/* capability granted */
		return 0;

	/* capability denied */
	return -EPERM;
}

static int rootplug_sys_security (unsigned int id, unsigned int call,
				  unsigned long *args)
{
	return -ENOSYS;
}

static int rootplug_quotactl (int cmds, int type, int id,
			      struct super_block *sb)
{
	return 0;
}

static int rootplug_quota_on (struct file *f)
{
	return 0;
}

static int rootplug_bprm_alloc_security (struct linux_binprm *bprm)
{
	return 0;
}

static void rootplug_bprm_free_security (struct linux_binprm *bprm)
{
	return;
}

static void rootplug_bprm_compute_creds (struct linux_binprm *bprm)
{
	return;
}

static int rootplug_bprm_set_security (struct linux_binprm *bprm)
{
	return 0;
}

static int rootplug_sb_alloc_security (struct super_block *sb)
{
	return 0;
}

static void rootplug_sb_free_security (struct super_block *sb)
{
	return;
}

static int rootplug_sb_statfs (struct super_block *sb)
{
	return 0;
}

static int rootplug_mount (char *dev_name, struct nameidata *nd, char *type,
			   unsigned long flags, void *data)
{
	return 0;
}

static int rootplug_check_sb (struct vfsmount *mnt, struct nameidata *nd)
{
	return 0;
}

static int rootplug_umount (struct vfsmount *mnt, int flags)
{
	return 0;
}

static void rootplug_umount_close (struct vfsmount *mnt)
{
	return;
}

static void rootplug_umount_busy (struct vfsmount *mnt)
{
	return;
}

static void rootplug_post_remount (struct vfsmount *mnt, unsigned long flags,
				   void *data)
{
	return;
}


static void rootplug_post_mountroot (void)
{
	return;
}

static void rootplug_post_addmount (struct vfsmount *mnt,
				    struct nameidata *nd)
{
	return;
}

static int rootplug_pivotroot (struct nameidata *old_nd,
			       struct nameidata *new_nd)
{
	return 0;
}

static void rootplug_post_pivotroot (struct nameidata *old_nd,
				     struct nameidata *new_nd)
{
	return;
}

static int rootplug_inode_alloc_security (struct inode *inode)
{
	return 0;
}

static void rootplug_inode_free_security (struct inode *inode)
{
	return;
}

static int rootplug_inode_create (struct inode *inode,
				  struct dentry *dentry,
				  int mask)
{
	return 0;
}

static void rootplug_inode_post_create (struct inode *inode,
					struct dentry *dentry,
					int mask)
{
	return;
}

static int rootplug_inode_link (struct dentry *old_dentry,
				struct inode *inode,
				struct dentry *new_dentry)
{
	return 0;
}

static void rootplug_inode_post_link (struct dentry *old_dentry,
				      struct inode *inode,
				      struct dentry *new_dentry)
{
	return;
}

static int rootplug_inode_unlink (struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int rootplug_inode_symlink (struct inode *inode, struct dentry *dentry,
				   const char *name)
{
	return 0;
}

static void rootplug_inode_post_symlink (struct inode *inode,
					 struct dentry *dentry,
					 const char *name)
{
	return;
}

static int rootplug_inode_mkdir (struct inode *inode,
				 struct dentry *dentry,
				 int mask)
{
	return 0;
}

static void rootplug_inode_post_mkdir (struct inode *inode,
				       struct dentry *dentry,
				       int mask)
{
	return;
}

static int rootplug_inode_rmdir (struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int rootplug_inode_mknod (struct inode *inode, struct dentry *dentry,
				 int major, dev_t minor)
{
	return 0;
}

static void rootplug_inode_post_mknod (struct inode *inode,
				       struct dentry *dentry,
				       int major, dev_t minor)
{
	return;
}

static int rootplug_inode_rename (struct inode *old_inode,
				  struct dentry *old_dentry,
				  struct inode *new_inode,
				  struct dentry *new_dentry)
{
	return 0;
}

static void rootplug_inode_post_rename (struct inode *old_inode,
					struct dentry *old_dentry,
					struct inode *new_inode,
					struct dentry *new_dentry)
{
	return;
}

static int rootplug_inode_readlink (struct dentry *dentry)
{
	return 0;
}

static int rootplug_inode_follow_link (struct dentry *dentry,
				       struct nameidata *nameidata)
{
	return 0;
}

static int rootplug_inode_permission (struct inode *inode, int mask)
{
	return 0;
}

static int rootplug_inode_permission_lite (struct inode *inode, int mask)
{
	return 0;
}

static int rootplug_inode_setattr (struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int rootplug_inode_getattr (struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

static void rootplug_post_lookup (struct inode *ino, struct dentry *d)
{
	return;
}

static void rootplug_delete (struct inode *ino)
{
	return;
}

static int rootplug_inode_setxattr (struct dentry *dentry, char *name,
				    void *value, size_t size, int flags)
{
	return 0;
}

static int rootplug_inode_getxattr (struct dentry *dentry, char *name)
{
	return 0;
}

static int rootplug_inode_listxattr (struct dentry *dentry)
{
	return 0;
}

static int rootplug_inode_removexattr (struct dentry *dentry, char *name)
{
	return 0;
}

static int rootplug_file_permission (struct file *file, int mask)
{
	return 0;
}

static int rootplug_file_alloc_security (struct file *file)
{
	return 0;
}

static void rootplug_file_free_security (struct file *file)
{
	return;
}

static int rootplug_file_llseek (struct file *file)
{
	return 0;
}

static int rootplug_file_ioctl (struct file *file, unsigned int command,
				unsigned long arg)
{
	return 0;
}

static int rootplug_file_mmap (struct file *file, unsigned long prot,
			       unsigned long flags)
{
	return 0;
}

static int rootplug_file_mprotect (struct vm_area_struct *vma,
				   unsigned long prot)
{
	return 0;
}

static int rootplug_file_lock (struct file *file, unsigned int cmd)
{
	return 0;
}

static int rootplug_file_fcntl (struct file *file, unsigned int cmd,
				unsigned long arg)
{
	return 0;
}

static int rootplug_file_set_fowner (struct file *file)
{
	return 0;
}

static int rootplug_file_send_sigiotask (struct task_struct *tsk,
					 struct fown_struct *fown,
					 int fd, int reason)
{
	return 0;
}

static int rootplug_file_receive (struct file *file)
{
	return 0;
}

static int rootplug_task_create (unsigned long clone_flags)
{
	return 0;
}

static int rootplug_task_alloc_security (struct task_struct *p)
{
	return 0;
}

static void rootplug_task_free_security (struct task_struct *p)
{
	return;
}

static int rootplug_task_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	return 0;
}

static int rootplug_task_post_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	return 0;
}

static int rootplug_task_setgid (gid_t id0, gid_t id1, gid_t id2, int flags)
{
	return 0;
}

static int rootplug_task_setpgid (struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int rootplug_task_getpgid (struct task_struct *p)
{
	return 0;
}

static int rootplug_task_getsid (struct task_struct *p)
{
	return 0;
}

static int rootplug_task_setgroups (int gidsetsize, gid_t * grouplist)
{
	return 0;
}

static int rootplug_task_setnice (struct task_struct *p, int nice)
{
	return 0;
}

static int rootplug_task_setrlimit (unsigned int resource, struct rlimit *new_rlim)
{
	return 0;
}

static int rootplug_task_setscheduler (struct task_struct *p, int policy,
				       struct sched_param *lp)
{
	return 0;
}

static int rootplug_task_getscheduler (struct task_struct *p)
{
	return 0;
}

static int rootplug_task_wait (struct task_struct *p)
{
	return 0;
}

static int rootplug_task_kill (struct task_struct *p,
			       struct siginfo *info,
			       int sig)
{
	return 0;
}

static int rootplug_task_prctl (int option,
				unsigned long arg2,
				unsigned long arg3,
				unsigned long arg4,
				unsigned long arg5)
{
	return 0;
}

static void rootplug_task_kmod_set_label (void)
{
	return;
}

static void rootplug_task_reparent_to_init (struct task_struct *p)
{
	p->euid = p->fsuid = 0;
	return;
}

static int rootplug_register (const char *name, struct security_operations *ops)
{
	return -EINVAL;
}

static int rootplug_unregister (const char *name, struct security_operations *ops)
{
	return -EINVAL;
}


/* the interesting stuff... */

/* default is a generic type of usb to serial converter */
static int vendor_id = 0x0557;
static int product_id = 0x2008;

MODULE_PARM(vendor_id, "h");
MODULE_PARM_DESC(vendor_id, "USB Vendor ID of device to look for");

MODULE_PARM(product_id, "h");
MODULE_PARM_DESC(product_id, "USB Product ID of device to look for");


/* should we print out debug messages */
static int debug = 0;

MODULE_PARM(debug, "i");
MODULE_PARM_DESC(debug, "Debug enabled or not");

#if defined(CONFIG_SECURITY_ROOTPLUG_MODULE)
#define MY_NAME THIS_MODULE->name
#else
#define MY_NAME "root_plug"
#endif

#define dbg(fmt, arg...)					\
	do {							\
		if (debug)					\
			printk(KERN_DEBUG "%s: %s: " fmt ,	\
				MY_NAME , __FUNCTION__ , 	\
				## arg);			\
	} while (0)

extern struct list_head usb_bus_list;
extern struct semaphore usb_bus_list_lock;

static int match_device (struct usb_device *dev)
{
	int retval = -ENODEV;
	int child;

	dbg ("looking at vendor %d, product %d\n",
	     dev->descriptor.idVendor,
	     dev->descriptor.idProduct);

	/* see if this device matches */
	if ((dev->descriptor.idVendor == vendor_id) &&
	    (dev->descriptor.idProduct == product_id)) {
		dbg ("found the device!\n");
		retval = 0;
		goto exit;
	}

	/* look through all of the children of this device */
	for (child = 0; child < dev->maxchild; ++child) {
		if (dev->children[child]) {
			retval = match_device (dev->children[child]);
			if (retval == 0)
				goto exit;
		}
	}
exit:
	return retval;
}

static int find_usb_device (void)
{
	struct list_head *buslist;
	struct usb_bus *bus;
	int retval = -ENODEV;
	
	down (&usb_bus_list_lock);
	for (buslist = usb_bus_list.next;
	     buslist != &usb_bus_list; 
	     buslist = buslist->next) {
		bus = container_of (buslist, struct usb_bus, bus_list);
		retval = match_device(bus->root_hub);
		if (retval == 0)
			goto exit;
	}
exit:
	up (&usb_bus_list_lock);
	return retval;
}
	

static int rootplug_bprm_check_security (struct linux_binprm *bprm)
{
	dbg ("file %s, e_uid = %d, e_gid = %d\n",
	     bprm->filename, bprm->e_uid, bprm->e_gid);

	if (bprm->e_gid == 0) {
		if (find_usb_device() != 0) {
			dbg ("e_gid = 0, and device not found, "
				"task not allowed to run...\n");
			return -EPERM;
		}
	}

	return 0;
}

static struct security_operations rootplug_security_ops = {
	.ptrace =			rootplug_ptrace,
	.capget =			rootplug_capget,
	.capset_check =			rootplug_capset_check,
	.capset_set =			rootplug_capset_set,
	.acct =				rootplug_acct,
	.capable =			rootplug_capable,
	.sys_security =			rootplug_sys_security,
	.quotactl =			rootplug_quotactl,
	.quota_on =			rootplug_quota_on,

	.bprm_alloc_security =		rootplug_bprm_alloc_security,
	.bprm_free_security =		rootplug_bprm_free_security,
	.bprm_compute_creds =		rootplug_bprm_compute_creds,
	.bprm_set_security =		rootplug_bprm_set_security,
	.bprm_check_security =		rootplug_bprm_check_security,

	.sb_alloc_security =		rootplug_sb_alloc_security,
	.sb_free_security =		rootplug_sb_free_security,
	.sb_statfs =			rootplug_sb_statfs,
	.sb_mount =			rootplug_mount,
	.sb_check_sb =			rootplug_check_sb,
	.sb_umount =			rootplug_umount,
	.sb_umount_close =		rootplug_umount_close,
	.sb_umount_busy =		rootplug_umount_busy,
	.sb_post_remount =		rootplug_post_remount,
	.sb_post_mountroot =		rootplug_post_mountroot,
	.sb_post_addmount =		rootplug_post_addmount,
	.sb_pivotroot =			rootplug_pivotroot,
	.sb_post_pivotroot =		rootplug_post_pivotroot,
	
	.inode_alloc_security =		rootplug_inode_alloc_security,
	.inode_free_security =		rootplug_inode_free_security,
	.inode_create =			rootplug_inode_create,
	.inode_post_create =		rootplug_inode_post_create,
	.inode_link =			rootplug_inode_link,
	.inode_post_link =		rootplug_inode_post_link,
	.inode_unlink =			rootplug_inode_unlink,
	.inode_symlink =		rootplug_inode_symlink,
	.inode_post_symlink =		rootplug_inode_post_symlink,
	.inode_mkdir =			rootplug_inode_mkdir,
	.inode_post_mkdir =		rootplug_inode_post_mkdir,
	.inode_rmdir =			rootplug_inode_rmdir,
	.inode_mknod =			rootplug_inode_mknod,
	.inode_post_mknod =		rootplug_inode_post_mknod,
	.inode_rename =			rootplug_inode_rename,
	.inode_post_rename =		rootplug_inode_post_rename,
	.inode_readlink =		rootplug_inode_readlink,
	.inode_follow_link =		rootplug_inode_follow_link,
	.inode_permission =		rootplug_inode_permission,
	.inode_permission_lite =	rootplug_inode_permission_lite,
	.inode_setattr =		rootplug_inode_setattr,
	.inode_getattr =		rootplug_inode_getattr,
	.inode_post_lookup =		rootplug_post_lookup,
	.inode_delete =			rootplug_delete,
	.inode_setxattr =		rootplug_inode_setxattr,
	.inode_getxattr =		rootplug_inode_getxattr,
	.inode_listxattr =		rootplug_inode_listxattr,
	.inode_removexattr =		rootplug_inode_removexattr,

	.file_permission =		rootplug_file_permission,
	.file_alloc_security =		rootplug_file_alloc_security,
	.file_free_security =		rootplug_file_free_security,
	.file_llseek =			rootplug_file_llseek,
	.file_ioctl =			rootplug_file_ioctl,
	.file_mmap =			rootplug_file_mmap,
	.file_mprotect =		rootplug_file_mprotect,
	.file_lock =			rootplug_file_lock,
	.file_fcntl =			rootplug_file_fcntl,
	.file_set_fowner =		rootplug_file_set_fowner,
	.file_send_sigiotask =		rootplug_file_send_sigiotask,
	.file_receive =			rootplug_file_receive,

	.task_create =			rootplug_task_create,
	.task_alloc_security =		rootplug_task_alloc_security,
	.task_free_security =		rootplug_task_free_security,
	.task_setuid =			rootplug_task_setuid,
	.task_post_setuid =		rootplug_task_post_setuid,
	.task_setgid =			rootplug_task_setgid,
	.task_setpgid =			rootplug_task_setpgid,
	.task_getpgid =			rootplug_task_getpgid,
	.task_getsid =			rootplug_task_getsid,
	.task_setgroups =		rootplug_task_setgroups,
	.task_setnice =			rootplug_task_setnice,
	.task_setrlimit =		rootplug_task_setrlimit,
	.task_setscheduler =		rootplug_task_setscheduler,
	.task_getscheduler =		rootplug_task_getscheduler,
	.task_wait =			rootplug_task_wait,
	.task_kill =			rootplug_task_kill,
	.task_prctl =			rootplug_task_prctl,
	.task_kmod_set_label =		rootplug_task_kmod_set_label,
	.task_reparent_to_init =	rootplug_task_reparent_to_init,

	.register_security =		rootplug_register,
	.unregister_security =		rootplug_unregister,
};

static int __init rootplug_init (void)
{
	/* register ourselves with the security framework */
	if (register_security (&rootplug_security_ops)) {
		printk (KERN_INFO 
			"Failure registering Root Plug module with the kernel\n");
		/* try registering with primary module */
		if (mod_reg_security (MY_NAME, &rootplug_security_ops)) {
			printk (KERN_INFO "Failure registering Root Plug "
				" module with primary security module.\n");
			return -EINVAL;
		}
		secondary = 1;
	}
	printk (KERN_INFO "Root Plug module initialized, "
		"vendor_id = %4.4x, product id = %4.4x\n", vendor_id, product_id);
	return 0;
}

static void __exit rootplug_exit (void)
{
	/* remove ourselves from the security framework */
	if (secondary) {
		if (mod_unreg_security (MY_NAME, &rootplug_security_ops))
			printk (KERN_INFO "Failure unregistering Root Plug "
				" module with primary module.\n");
	} else { 
		if (unregister_security (&rootplug_security_ops)) {
			printk (KERN_INFO "Failure unregistering Root Plug "
				"module with the kernel\n");
		}
	}
	printk (KERN_INFO "Root Plug module removed\n");
}

module_init (rootplug_init);
module_exit (rootplug_exit);

MODULE_DESCRIPTION("Root Plug sample LSM module, written for Linux Journal article");
MODULE_LICENSE("GPL");

