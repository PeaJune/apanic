/* drivers/misc/apanic.c
 *
 * Copyright (C) 2009 Google, Inc.
 * Author: San Mehat <san@android.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/wait.h>
//#include <linux/wakelock.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/mtd/mtd.h>
#include <linux/notifier.h>
#include <linux/mtd/mtd.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/preempt.h>

#include <linux/kernel.h>			//for do_sysinfo()
#include <linux/time.h>				//CURRENT_TIME

#include <linux/slab.h>

//extern void ram_console_enable_console(int);

struct panic_header {
	u32 magic;
#define PANIC_MAGIC 0xdeadf00d

	u32 version;
#define PHDR_VERSION   0x01

	u32 console_offset;
	u32 console_length;

	u32 threads_offset;
	u32 threads_length;
};

struct apanic_data {
	struct mtd_info		*mtd;
	struct panic_header	curr;
	void			*bounce;
	struct proc_dir_entry	*apanic_console;
	struct proc_dir_entry	*apanic_threads;
	struct proc_dir_entry	*apanic_all;
};

static struct apanic_data drv_ctx;
static DEFINE_MUTEX(drv_mutex);

extern int panic_do_sysinfo(struct sysinfo *info);


static void apanic_erase_callback(struct erase_info *done)
{
	wait_queue_head_t *wait_q = (wait_queue_head_t *) done->priv;
	wake_up(wait_q);
}

static void mtd_panic_erase(void)
{
	struct apanic_data *ctx = &drv_ctx;
	struct erase_info erase;
	DECLARE_WAITQUEUE(wait, current);
	wait_queue_head_t wait_q;
	int rc, i;
	struct mtd_info *mtd;
	mtd = ctx->mtd;


	init_waitqueue_head(&wait_q);
	erase.mtd = ctx->mtd;
	erase.callback = apanic_erase_callback;
	erase.len = ctx->mtd->erasesize;
	erase.priv = (u_long)&wait_q;

	for (i = 0; i < ctx->mtd->size; i += ctx->mtd->erasesize) {
		erase.addr = i;
		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&wait_q, &wait);

		rc = ctx->mtd->_erase(ctx->mtd, &erase);
		if (rc) {
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&wait_q, &wait);
			printk(KERN_ERR
			       "apanic: Erase of 0x%llx, 0x%llx failed\n",
			       (unsigned long long) erase.addr,
			       (unsigned long long) erase.len);
			if (rc == -EIO) {
				if (ctx->mtd->_block_markbad(ctx->mtd,
							    erase.addr)) {
					printk(KERN_ERR
					       "apanic: Err marking blk bad\n");
					goto out;
				}
				printk(KERN_INFO
				       "apanic: Marked a bad block"
				       " @%llx\n", erase.addr);
				continue;
			}
			goto out;
		}
		schedule();
		remove_wait_queue(&wait_q, &wait);
	}

	printk(KERN_INFO "apanic: %s partition erased\n",
	       CONFIG_APANIC_PLABEL);
out:
	return;
}


static void mtd_panic_notify_add(struct mtd_info *mtd)
{
	struct apanic_data *ctx = &drv_ctx;
	struct panic_header *hdr = ctx->bounce;
	size_t len;
	int rc;

	if (strcmp(mtd->name, CONFIG_APANIC_PLABEL))
		return;

	ctx->mtd = mtd;

	rc = mtd->_read(mtd, 0, sizeof(struct panic_header),
			&len, ctx->bounce);

	if (rc && rc == -EBADMSG) {
		printk(KERN_WARNING
		       "apanic: Bad ECC on block 0 (ignored)\n");
	} else if (rc && rc != -EUCLEAN) {
		printk(KERN_ERR "apanic: Error reading block 0 (%d)\n", rc);
		goto out_err;
	}

	if (len != sizeof(struct panic_header)) {
		printk(KERN_ERR "apanic: Bad read size (%d)\n", rc);
		goto out_err;
	}

	printk(KERN_INFO "apanic: Bound to mtd partition '%s'\n", mtd->name);

	if (hdr->magic == 0xffffffff && hdr->version == 0xffffffff) {
		printk(KERN_INFO "apanic: %s already erased\n", mtd->name);
		return;
	}

	if (hdr->magic != PANIC_MAGIC) {
		printk(KERN_INFO "apanic: No panic data available\n");
		mtd_panic_erase();
		return;
	}

	if (hdr->version != PHDR_VERSION) {
		printk(KERN_INFO "apanic: Version mismatch (%d != %d)\n",
		       hdr->version, PHDR_VERSION);
		mtd_panic_erase();
		return;
	}

	memcpy(&ctx->curr, hdr, sizeof(struct panic_header));

	printk(KERN_INFO "apanic: c(%u, %u) t(%u, %u)\n",
	       hdr->console_offset, hdr->console_length,
	       hdr->threads_offset, hdr->threads_length);

	return;
out_err:
	ctx->mtd = NULL;
}

static void mtd_panic_notify_remove(struct mtd_info *mtd)
{
	struct apanic_data *ctx = &drv_ctx;
	if (mtd == ctx->mtd) {
		ctx->mtd = NULL;
		printk(KERN_INFO "apanic: Unbound from %s\n", mtd->name);
	}
}

static struct mtd_notifier mtd_panic_notifier = {
	.add	= mtd_panic_notify_add,
	.remove	= mtd_panic_notify_remove,
};

static int in_panic = 0;


/*
 * Writes the contents of the console to the specified offset in flash.
 * Returns number of bytes written
 */
extern int apanic_syslog_print_all(struct mtd_info *mtd, int off, char __user *buf, int size, bool clear);
static int apanic_write_console(struct mtd_info *mtd, unsigned int off)
{
	char *buf = (char *)kmalloc(4, GFP_KERNEL);

	return apanic_syslog_print_all(mtd, off, buf, mtd->size, 0);

#if 0
	int rc;
	char *ch;
	u32 log_len;
	u32 wlen =0;
	u32 total_len = 0;
	u32 first_idx = 0;
	u32 next_idx = 0;

	ch = log_buf_addr_get();
	log_len = log_buf_len_get();

	first_idx = log_first_idx_get();
	next_idx = log_next_idx_get();

#if 0
	 /*debug info*/
	 printk(KERN_EMERG "----------------log_len: %d\n", log_len);
	 printk(KERN_EMERG "--------------first idx: %d\n", first_idx);
	 printk(KERN_EMERG "---------------next_idx: %d\n", next_idx);
#endif
	if(next_idx >= first_idx)	
	{
		/*if ring buffer not overwrite old log, then directly copy first_idx to next_idx log to flash*/
		rc = mtd->_write(mtd, off, next_idx - first_idx, &total_len, ch + first_idx);
	}else{	
		/*if ring buffer overwrite old log, then need to copy first_idx to buffer end  and buffer start to next_idx to flash*/
		/*				  |--------------ring buffer---------------------*/
		/*the fisrt part: |________________|_____________________________|*/
		/*				  |				   |------------first part-------|	*/
		/*				  |--second part---|							 |	*/
		rc = mtd->_write(mtd, off, log_len - first_idx, &wlen, ch + first_idx);
		rc = mtd->_write(mtd, off + (log_len- first_idx), next_idx, &total_len, ch);
	}

	if(rc <= 0)
	{
		/*return write error, but exactly the flash is writed success*/
		//printk(KERN_EMERG "apanic: Flash write failed (%d)\n", wlen);
	}

	return total_len + wlen;
#endif
}

static int apanic(struct notifier_block *this, unsigned long event,
			void *ptr)
{
	struct apanic_data *ctx = &drv_ctx;
	struct panic_header *hdr = (struct panic_header *) ctx->bounce;
	int console_offset = 0;
	int console_len = 0;
	int threads_offset = 0;
	int threads_len = 0;
	int rc;
	struct mtd_info *mtd;
	int wlen = 0;

	mtd = ctx->mtd;

	if (in_panic)
		return NOTIFY_DONE;
	in_panic = 1;
#ifdef CONFIG_PREEMPT
	/* Ensure that cond_resched() won't try to preempt anybody */
	add_preempt_count(PREEMPT_ACTIVE);
#endif
	touch_softlockup_watchdog();

	if (!ctx->mtd)
		goto out;

	if (ctx->curr.magic) {
		printk(KERN_EMERG "Crash partition in use!\n");
		goto out;
	}
	console_offset = sizeof(struct panic_header);
	//ctx->mtd->writesize * ctx->mtd->erasesize;

	/*
	 * Write all out the console
	 */
	show_state_filter(0);
	console_len = apanic_write_console(ctx->mtd, console_offset);
	if (console_len < 0) {
		printk(KERN_EMERG "Error writing console to panic log! (%d)\n",
		       console_len);
		console_len = 0;
	}
	/*
	 * Finally write the panic header
	 */
	memset(ctx->bounce, 0, PAGE_SIZE);
	hdr->magic = PANIC_MAGIC;
	hdr->version = PHDR_VERSION;

	hdr->console_offset = console_offset;
	hdr->console_length = console_len;

	hdr->threads_offset = threads_offset;
	hdr->threads_length = threads_len;

	rc = mtd->_write(mtd, 0, sizeof(struct panic_header), &wlen, ctx->bounce);
	if (rc <= 0) {
		//printk(KERN_EMERG "apanic: Header write failed (%d)\n",rc);
		//goto out;
	}

	printk(KERN_EMERG "apanic: Panic dump sucessfully written to flash c(%u, %u) t(%u, %u) h(%u)\n",
	       hdr->console_offset, hdr->console_length,
	       hdr->threads_offset, hdr->threads_length,
	       rc);

 out:
#ifdef CONFIG_PREEMPT
	sub_preempt_count(PREEMPT_ACTIVE);
#endif
	in_panic = 0;
	return NOTIFY_DONE;
}

#define xstr(s) astr(s)
#define astr(s)  #s

static int apanic_pre(struct notifier_block *this, unsigned long event,
			void *ptr)
{
/* time */
	struct sysinfo si;
	unsigned int days_up, hours_up, minutes_up, seconds_up, working_uptime;
	struct tm crash_date;

	//Version
	//printk(KERN_INFO "Version       : aoslite-%s\n", xstr(CONFIG_VERSION_CONFIG_VERSIONID));
	printk(KERN_INFO "Version       : netra-portable \n");

	//Time
	time_to_tm(CURRENT_TIME.tv_sec, 0, &crash_date);
	printk(KERN_INFO "crash date    : %4d-%02d-%02d  %2d:%02d:%02d GMT\n",
			(int)(crash_date.tm_year+1900), crash_date.tm_mon+1, crash_date.tm_mday,
			crash_date.tm_hour, crash_date.tm_min, crash_date.tm_sec);

	/*
	 * Sysinfo
	 */
	panic_do_sysinfo(&si);
	working_uptime  = si.uptime;
	days_up         = working_uptime / 86400;
	working_uptime -= days_up        * 86400;
	hours_up        = working_uptime / 3600;
	working_uptime -= hours_up       * 3600;
	minutes_up      = working_uptime / 60;
	working_uptime -= minutes_up     * 60;
	seconds_up      = working_uptime;
	printk(KERN_INFO "Uptime        : %u days, %u hours, %u minutes, %u seconds\n",
			days_up, hours_up, minutes_up, seconds_up);
	printk(KERN_INFO "Load Avgs     : 1min(%ld) 5min(%ld) 15min(%ld)\n",
			si.loads[0], si.loads[1], si.loads[2]);
	printk(KERN_INFO "Total Ram     : %ldk \t Free: %ldk \n", si.totalram / 1024, si.freeram / 1024);
	printk(KERN_INFO "Shared Ram    : %ldk \n", si.sharedram / 1024);
	printk(KERN_INFO "Buffered Ram  : %ldk \n", si.bufferram / 1024);
	printk(KERN_INFO "Total Swap    : %ldk \t Free swap: %ldk \n", si.totalswap / 1024, si.freeswap / 1024);
	printk(KERN_INFO "Total High Mem: %ldk \t Free high memory: %ldk \n", si.totalhigh / 1024, si.freehigh / 1024);
	printk(KERN_INFO "Total process : %d \n", si.procs);


	return NOTIFY_DONE;
}

static struct notifier_block panic_blk = {
	.notifier_call	= apanic,
};

static struct notifier_block panic_blk_before_apanic = {
	.notifier_call	= apanic_pre,
};
#if 0
static int panic_dbg_get(void *data, u64 *val)
{
	struct apanic_data *ctx = &drv_ctx;
	//struct panic_header *hdr = (struct panic_header *) ctx->bounce; 
	
	printk(KERN_EMERG "crash dump info size: %d", ctx->cur.console_length);
	*val = ctx->curr.console_length;
//	apanic_pre(NULL, 0, NULL);
//	apanic(NULL, 0, NULL);
	return 0;
}

static int panic_dbg_set(void *data, u64 val)
{
	//BUG();
	memset(&drv_ctx, 0, sizeof(drv_ctx));
	printk(KERN_EMERG "clear curr carsh dump inof\n");
	return -1;
}
#endif

static int apanic_proc_open(struct inode *inode, struct file *filp)
{
	int *private = (int*)kmalloc(4, GFP_KERNEL);
	
	filp->private_data = private;
	
	*private = 0;

	return 0;
}

static int apanic_proc_read(struct file *filp, char *buf, size_t count, loff_t *offp)
{
	char info[64] = "";	
	struct apanic_data *ctx = &drv_ctx;
	int *private = NULL;

	private = filp->private_data;


	sprintf(info, "%d", ctx->curr.console_length);

	copy_to_user(buf,info, strlen(info) +1);
	//printk(KERN_EMERG "crash dump info size: %d", ctx->curr.console_length);

	if(*private == 0)
	{
		*private = 1;
		return strlen(info) + 1;
	}
	return 0;
}

static int apanic_proc_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
	struct apanic_data *ctx = &drv_ctx;
	struct panic_header *panic_h = &(ctx->curr);

	memset(panic_h, 0, sizeof(struct panic_header));
	//printk(KERN_EMERG "clear curr carsh dump inof\n");
	return  count;
}

static const struct file_operations apanic_proc_fops = {
	.open		=	apanic_proc_open,
	.read		=	apanic_proc_read,
	.write		=	apanic_proc_write,
};

//DEFINE_SIMPLE_ATTRIBUTE(panic_dbg_fops, panic_dbg_get, panic_dbg_set, "%llu\n");

int __init apanic_init(void)
{
	register_mtd_user(&mtd_panic_notifier);
	atomic_notifier_chain_register(&panic_notifier_list, &panic_blk_before_apanic);
	atomic_notifier_chain_register(&panic_notifier_list, &panic_blk);
	memset(&drv_ctx, 0, sizeof(drv_ctx));
	proc_create("apanic", 0, NULL, &apanic_proc_fops);
	//debugfs_create_file("apanic", 0644, NULL, NULL, &panic_dbg_fops);
	drv_ctx.bounce = (void *) __get_free_page(GFP_KERNEL);
	printk(KERN_INFO "Android kernel panic handler initialized (bind=%s)\n",
	       CONFIG_APANIC_PLABEL);
	return 0;
}

module_init(apanic_init);
