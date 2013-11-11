#ifndef _SYS_TIME_H
#define _SYS_TIME_H

#include <linux/time.h>

#if BITS_PER_LONG == 32
extern long long get_current_time(void);
#elif BITS_PER_LONG == 64
extern long get_current_time(void);
#endif

#define current_time (get_current_time())
#if 0
struct timeval {
    long    tv_sec;         /* seconds */
    long    tv_usec;        /* microseconds */
};

struct timespec {
    long    tv_sec;         /* seconds */
    long    tv_nsec;        /* nanoseconds */
};

struct timezone {
    int tz_minuteswest;     /* minutes west of Greenwich */
    int tz_dsttime;         /* type of DST correction */
};

#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
#define CLOCK_MONOTONIC_RAW		4
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
#endif

#endif
