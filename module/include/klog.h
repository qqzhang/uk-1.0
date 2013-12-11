#include <linux/kernel.h>
//#include <linux/module.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/smp.h>

#define KLOG

#ifdef KLOG
#define REFCNT(obj) ( (obj) ? (((struct object*)(obj))->refcount) : (0xffff) )
#define klog(trace,FMT...) \
	do { \
		printk("UK: (%s:%d) cpu %d p %d t %d %s ",strrchr(__FILE__,'/'),__LINE__, smp_processor_id(), current->tgid, current->pid, __FUNCTION__); \
		printk(FMT); \
		if(trace) dump_stack(); \
	} while (0)
#else
#define klog(FMT...) do { } while (0)
#endif


