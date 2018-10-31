#include <stdlib.h>

#include <dlfcn.h>
#include <sys/types.h>
// On the iPhone, however, <sys/ptrace.h> is not available



// we can directly disable any debugger currently or later attached to an application
// with the ptrace() function and the PT_DENY_ATTACH parameter. If a debugger is being
// attached to an application, a call to ptrace(PT_DENY_ATTACH, 0, 0, 0) will send a
// ENOTSUP signal and quit the current process. In the other case, if the application
// is running and a debugger tries to attach to it, a segmentation fault will occur.


// detect GDB and deny attach
// https://applidium.com/en/news/securing_ios_apps_debuggers/
// http://iphonedevwiki.net/index.php/Crack_prevention

// also refer to: check P_TRACED flag


// ptrototype of ptrace function
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);


// PT_DENY_ATTACH == 31, not defined in iOS
#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif  // !defined(PT_DENY_ATTACH)

// disable gdb debugger by calling ptrace in advance
void deny_ptrace_attach()
{
    void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);  // load dynamic librairies
    
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");  // pointer on ptrace function
    
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    
    dlclose(handle);
}

// TODO:
// the string "ptrace" should be obfuscated
// spam




// 去掉使用ptrace的反动态调试保护, by hook dlsym or hook ptrace function
// http://everettjf.github.io/2015/12/20/amap-ios-client-kill-anti-debugging-protect