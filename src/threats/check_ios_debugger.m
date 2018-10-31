#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <termios.h>

//#include <dlfcn.h>
//#include <execinfo.h>

#include "profile/appstatus.h"



// https://developer.apple.com/library/mac/qa/qa1361/_index.html

// Returns true if the current process is being debugged
// (either running under the debugger or has a debugger attached post facto).
// return:  0 -OK,  1-being debugged
static int is_pflag_set(int pid)
{
    // Note: It is possible to obfuscate this with ADVobfuscator (like the calls to getpid and sysctl)
    
    
        // check if kp_proc.p_flag from sysctl call is set to P_TRACED
        struct kinfo_proc info;
        info.kp_proc.p_flag = 0;
        
        size_t info_size = sizeof(info);
        
        int name[4];
        name[0] = CTL_KERN;
        name[1] = KERN_PROC;
        name[2] = KERN_PROC_PID;
        name[3] = pid;   // getpid()
        
        if (sysctl(name, 4, &info, &info_size, NULL, 0) != -1)
        {
            if ((info.kp_proc.p_flag & P_TRACED) != 0)
            {
                // being debugged on this pid
                printf("found debugger on process pid = %d\n", pid);
                return 1;
            }
        }
    
    return 0;
}


// 检查是否有GDB debugger
// this check can be spammed into program
int check_gdb_debugger()
{
    return is_pflag_set(getpid());
}




// 检查是否有LLDB debugger
int check_lldb_debugger()
{
    // lldb is attached
    struct winsize win;
    if (isatty(1) && !ioctl(1, TIOCGWINSZ, &win) && !win.ws_col)
    {
        printf("found lldb attached!\n");
        return 1;
    }
    
    return 0;
}


// API
int check_debugger()
{
    int status = 0;
    
    if ( check_gdb_debugger())
    {
        set_debugger_status(THREAT_DEBUGGER_GDB);
        status = 1;
    }
    
    if (check_lldb_debugger())
    {
        set_debugger_status(THREAT_DEBUGGER_LLDB);
        status = 2;
    }
    
    return status;
}

