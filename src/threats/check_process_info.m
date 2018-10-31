
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/errno.h>


//#import <Foundation/Foundation.h>
@import Foundation;
@import UIKit;


// 利用 sysctl 检查 pid 对应的process name是否出现可疑字符串如 sshd, cycript, gdb.
// sysctl 类似例子:  check_ios_debugger.m, check_tcp_ports.m


// http://psutil.googlecode.com/svn/trunk/psutil/arch/osx/process_info.c

 #define kKernProcPid_cstr                           		"kern.proc.pid"

 #define kSshd_ctsr                                  		"sshd"
 #define kGDB_cstr                                   		"gdb"
 #define kCycript_cstr                               		"cycript"

#define VG_IOS_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define VG_IOS_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define VG_IOS_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define VG_IOS_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define VG_IOS_VERSION_LESS_THAN_OR_EQUAL_TO(v)     ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

#define VG_IOS_9 @"9.0"



// Read the maximum argument size for processes
static int get_argmax()
{
    int argmax;
    int mib[] = { CTL_KERN, KERN_ARGMAX };
    size_t size = sizeof(argmax);
    
    if (sysctl(mib, 2, &argmax, &size, NULL, 0) == 0)
    {
        return argmax;
    }

    printf("warning: '%s' (%d) getting KERN_ARGMAX", strerror(errno), errno);
    return 4096;   // default
}


// Func: get full path for process with pid num, rather than p_comm
// This returns the full process name, rather than the 16 char limit
// the p_comm field of the proc struct is limited to.
// Note: this only works if the process is running under the same
// user you are, or you are running this code as root.  If not, then
// the p_comm field is used instead (this function returns nil).
static int check_process_path(int pid)
{
    int status = 0;
    
	int mib[] = {CTL_KERN, KERN_PROCARGS2, 0};
	mib[2] = pid;

    size_t size = get_argmax();

    // allocate buffer for sysctl call
	char *buffer = malloc(size);
    
	int ret = sysctl(mib, 3, buffer, &size, NULL, 0);
	if (ret != 0)
	{
		//printf("sysctl KERN_PROCARGS2 error: %d, errorno %d\n", ret, errno);
		free(buffer);
		return 0;
	}
    
    // KERN_PROCARGS2 needs to at least contain argc, whic is 32-bit integer.
    //  stringptr = buffer + sizeof(int);
    // do not use sizeof(size_t) because on it has problem in 64-bit.
    //printf("process name: %s\n", buffer + sizeof(int));
    
    char* stringptr = buffer + sizeof(int);
    if ( strstr(stringptr,  "/Developer/usr/bin/debugserver") )
    {
        status = 1;
        printf("found debugserver: %s\n", stringptr);
        //return 1; // found debugserver (xcode)
    }

    free(buffer);
    return status;
}


static int get_kinfo_proc(pid_t pid, struct kinfo_proc *kp)
{
    int mib[4];
    size_t len;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = pid;
    
    // fetch the info with sysctl()
    len = sizeof(struct kinfo_proc);
    
    // now read the data from sysctl
    if (sysctl(mib, 4, kp, &len, NULL, 0) == -1)
    {
        // raise an exception and throw errno as the error
        return -1;
    }
    
    // sysctl succeeds but len is zero, happens when process has gone away
    if (len == 0)
    {
        // NoSuchProcess();
        return -1;
    }
    
    return 0;
}


static int check_kinfo_proc(struct kinfo_proc *kp)
{
    int status = 0;   // 0 for OK
    
    // check process names
    if (strstr(kp->kp_proc.p_comm, kSshd_ctsr))
    {
        printf("kernel: sshd process %d", kp->kp_proc.p_pid);
        status = 1;  // found threat
    }
    else if (strstr(kp->kp_proc.p_comm, kGDB_cstr))
    {
        printf("kernel: gdb process %d", kp->kp_proc.p_pid);
        status = 1;
    }
    else if (strstr(kp->kp_proc.p_comm, kCycript_cstr))
    {
        printf("kernel: cycript process %d", kp->kp_proc.p_pid);
        status = 1;
    }
    
    if ( status > 0 )
    {
        printf("%5d %5d %5d %s\n", kp->kp_proc.p_pid, kp->kp_eproc.e_pgid, kp->kp_eproc.e_ppid, kp->kp_proc.p_comm);
        //print_process_path(i);
    }
    
    return status;
}


// 通过sysctl传递KERN_PROC，参数为KERN_PROC_ALL。这样可以获得当前的进程信息列表，
// 每个进程的信息通过结构体kinfo_proc来反映。
// 这里包含pid：kp->kp_proc.p_pid，然后在调用sysctl传递KERN_PROCARGS2，pid作为参数，就可以获得对应的运行参数.
int check_all_processes()
{
    const int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    struct kinfo_proc *info;
    size_t length;
    int count;  // number of processes
    
    if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
    {
        printf("KERN_PROC_ALL error:\n");   // 这里在iOS 9 non-jailbroken device上拿不到 process list.
        return 0;
    }
    
    if (!(info = malloc(length)))
        return 0;
    
    if (sysctl(mib, 3, info, &length, NULL, 0) < 0)
    {
        free(info);
        return 0;
    }
    
    count = length / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++)
    {
        pid_t pid = info[i].kp_proc.p_pid;
        printf("#%d: check pid %d\n", i, pid);
        if (pid == 0)  // root
        {
            continue;
        }
     
        check_kinfo_proc( &(info[i]) );
        check_process_path(pid);
    }
    
    free(info);
    
    return 0;
}


static int _check_kproc_pids(int pid_min, int pid_max)
{
	printf("check kernel process pids: %d-%d\n", pid_min, pid_max);
	int status = 0;   // 0 for OK

	//init for kernel check
	int mib[4];
	size_t plen;
	struct kinfo_proc kp;
	plen = 4;

    // fetching mib prefixes and then adding a final component.
    // For example, to fetch process infor-mation information mation for processes with pid
	int res = sysctlnametomib(kKernProcPid_cstr, mib, &plen);
	if (res == -1)
	{
		printf("sysctlnametomib error: %d", res);
		return 0;
	}

   	// check process list by sysctl
	for (int i = pid_min; i <= pid_max; i++)
	{
        // firstly check process full path
        if ( check_process_path(i) != 0 )
        {
            status = 1;
        }
        
        // secondly check p_comm in kinfo_proc.
		mib[3] = i;
		plen = sizeof(kp);
		res = sysctl(mib, 4, &kp, &plen, NULL, 0);
		if (res != -1 && plen > 0)  // kern.proc.pid sys call was blocked in ios9.0 and above
		{
            if ( check_kinfo_proc(&kp) != 0 )
            {
                status = 2;
            }
		}
	}

	return status;
}




// wrapper
// 目前在ios9上能发现debugserver.
int check_kproc_pids(void)
{
    // NOTE: iOS 9 appears to have blocked off access to kern.proc.pid;
    // this chunk of code checking the process listing should either be
    //       (a) replaced with something else, if we can research into other ways to access to;
    //       (b) left as-if, if it can still work, for example on jailbroken phones when the iOS 9 jailbreak comes out, or
    //       (c) removed entirely
    //
    // We have a lot stronger protections against gdb / cycript at runtime now so the importance of these checks have diminished
    //
    // Note also that Apple still allows access to the network process listing, but the same considerations could apply for that in future.
    // For now we have also made that chunk of code fail gracefully, in case Apple closes that off in future.
    
    
    // Due to kern.proc.pid sys call block in ios 9.0 onwards do only this test for bellow ios 9.0 versions.
    /*
    if (!VG_IOS_VERSION_LESS_THAN(VG_IOS_9))
    {
        printf("kproc check was disabled since ios9.0\n");
        return 0;
    }
    */
    
    // check process list by sysctl
    int pid_min = 0x0001;
    int pid_max = 0x8000;
    // PID_MAX_LIMIT: 32768 for 32-bit, 4194303 for 64-bit
    
    // another strategy: check nearby pids
    int pid = getpid();
    pid_min = pid > 200 ? (pid - 200): 0;
    pid_max = pid + 200;
    
    int status = _check_kproc_pids(pid_min, pid_max);
    //int status = check_all_processes();
    
    return status;
}


// TODO: 能否利用non-jailbroken ios9禁止了sysctl KERN_PROC 来判断是否已越狱(可以用sysctl)