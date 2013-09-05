#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#define KLOG

#ifdef KLOG
#define REFCNT(obj) \
	atomic_read(&(BODY_TO_HEADER((obj)))->PointerCount)

#define klog(trace,FMT...) \
	do { \
		printk("UK: (%s:%d) p %d t %d %s ",strrchr(__FILE__,'/'),__LINE__, current->tgid, current->pid, __FUNCTION__); \
		printk(FMT); \
		if(trace) dump_stack(); \
	} while (0)
#else
#define klog(FMT...) do { } while (0)
#endif


