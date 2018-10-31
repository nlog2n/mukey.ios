//
//  main.m
//  prog1
//
//
// MacOS terminal build
/*
$ clang -fobjc-arc -framework Foundation main.m -o prog1     #Compile main.m & call it prog1
$
*/


// refer to:  http://blog.csdn.net/yiyaaixuexi/article/details/20286929
//  http://stackoverflow.com/questions/5567215/how-to-determine-binary-image-architecture-at-runtime

#import <Foundation/Foundation.h>

#import <mach-o/dyld.h>
//#import <mach-o/loader.h>
//#import <mach-o/arch.h>

#include <string.h>

#import <sys/stat.h>
#import <dlfcn.h>


#include "profile/appstatus.h"



// 检测"/Applications/Cydia.app"等文件是否存在
// 比如对于Xcode simulator, 存在以下文件：
// found /bin/bash!
// found /bin/sh!
// found /usr/sbin/sshd!
// found /usr/libexec/ssh-keysign!
// found /usr/sbin/sshd!
// found /usr/libexec/sftp-server!

#define ARRAY_SIZE(a) sizeof(a)/sizeof(a[0])

const char* jailbreak_tool_pathes[] = {
  "/private/var/stash",
  "/private/var/lib/apt",
  "/private/var/tmp/cydia.log",
  "/private/var/lib/cydia",
  "/Library/MobileSubstrate/MobileSubstrate.dylib",
  "/Library/MobileSubstrate/DynamicLibraries/MobileSubstrate.dylib",
  "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
  "/var/cache/apt",
  "/var/lib/apt",
  "/var/lib/cydia",
  "/var/log/syslog",
  "/var/tmp/cydia.log",
  "/bin/bash",
  "/bin/sh",
  "/usr/libexec/cydia"
  "/etc/apt",
  "/Applications/Cydia.app"
};


// C functions like fopen(), stat(), or access() can be used to check file existence.
int check_cydia(void)
{
    int status = 0;
    struct stat stat_info;

    printf("check if cydia files exist: ");
    for (int i = 0; i < ARRAY_SIZE(jailbreak_tool_pathes); i++)
    {
    if ( stat(jailbreak_tool_pathes[i], &stat_info) == 0 ) // success
    {
        printf("found %s!\n", jailbreak_tool_pathes[i]);
        status = 1+ i;
        set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_FILES + i);
        
        break;
    }
    }

    printf( status == 0 ? "OK\n": "Fail\n");
    return status;
}

// special check on /etc/fstab file size
int check_fstab_file(void)
{
    int status = 0;
    struct stat stat_info;
    
    printf("check /etc/fstab file size: ");
    if ( stat("/etc/fstab", &stat_info) == 0 )
    {
        printf(" %d\n", (int) (stat_info.st_size));
        if ( stat_info.st_size != 80 )
        {
            status = 1;
            set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_FILE_FSTAB);
        }
    }
    
    printf( status == 0 ? "OK\n": "Fail\n");
    return status;
}


// 检查特定的文件是否是符号链接文件: if yes, then jailbroken
// 使用lstat()，检查以下文件是否为符号链接文件
int is_linkfile_existed(void)
{
    int status = 0;
    struct stat stat_info;
    
    if ( lstat("/Library/Wallpaper", &stat_info) == 0 )
    {
        if (stat_info.st_mode & S_IFLNK)
        {
            status = 1;
            set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_FILE_LINKED + 1);
        }
    }
    else if ( lstat("/Library/Ringtones", &stat_info) == 0 )
    {
        if (stat_info.st_mode & S_IFLNK)
        {
            status = 2;
            set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_FILE_LINKED + 2);
        }
    }
    else if ( lstat("/Applications", &stat_info) == 0 )
    {
        if (stat_info.st_mode & S_IFLNK)
        {
            status = 3;
            set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_FILE_LINKED + 3);
        }
    }
    else if ( lstat("/usr/share", &stat_info) == 0 )
    {
        if (stat_info.st_mode & S_IFLNK)
        {
            status = 4;
            set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_FILE_LINKED + 4);
        }
    }
    else if ( lstat("/usr/include", &stat_info) == 0 )
    {
        if (stat_info.st_mode & S_IFLNK)
        {
            status = 5;
            set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_FILE_LINKED + 5);
        }
    }
    else if ( lstat("/usr/libexec", &stat_info) == 0 )
    {
        if (stat_info.st_mode & S_IFLNK)
        {
            status = 6;
            set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_FILE_LINKED + 6);
        }
    }
    
    printf("check any linked file existed: %d\n", status);
    return status;
}


// sandbox integrity check
// 在越狱的机器上可以创建, 如果沙盒被破话，可以创建子进程
// 对于Xcode simulator, 也可以创建子进程。
int check_fork(void)
{
  int child = fork(); //这个函数从这里起，程序被分为两个进程父和子:
  // 子进程，返回0，父进程返回子进程ID，如果执行fork成功，说明沙盒被破坏，说明越狱了
  if (!child) //子进程，关闭他
  {
    exit(0);
  }
  if (child > 0) // 父进程，说明越狱
  {
    printf("check fork: jailbroken\n");
      set_root_jailbreak_status(THREAT_JAILBREAK_FORK_CHILD_PROCESS);
    return 1;
  }

  printf("check fork:  OK\n");
  return 0 ;// fork 出错返回-1， 判断为正常情况(没有越狱)
}

// 看函数stat是不是出自系统库，有没有被攻击者换掉
// check if the function, "stat", has been replaced/hooked
//  which should come from "/usr/lib/system/libsystem_kernel.dylib"
// 对于Xcode simulator, 该函数存在于
// /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk/usr/lib/system/libsystem_sim_kernel.dylib
int check_hooked_function(void)
{
    int ret ;
    Dl_info info;
    int status = 0;
    
    printf("check function stat integrity: ");
    
    int (*func_stat)(const char *, struct stat *) = stat;
    if ((ret = dladdr(func_stat, &info)))
    {
    if ( strcmp(info.dli_fname, "/usr/lib/system/libsystem_kernel.dylib") != 0 )
    {
        // hooked
        status = 1;
        printf("hooked in lib :%s\n", info.dli_fname);
        set_root_jailbreak_status(THREAT_JAILBREAK_FUNCTION_HOOKED);
        
        if ( strstr(info.dli_fname, "/usr/lib/system/libsystem_sim_kernel.dylib") != 0
            && strstr(info.dli_fname, "Xcode") != 0
            && strstr(info.dli_fname, "iPhoneSimulator") != 0 )
        {
            printf("for xcode simulator\n");
            status = 2;
            set_simulator_status(THREAT_SIMULATOR_XCODE);
            set_debugger_status(THREAT_DEBUGGER_XCODE);
        }
    }
    }

    printf( status == 0 ? "OK\n": "Fail\n");
    return status;
}

// 列出所有已链接的动态库, 检索一下自己的应用程序是否被链接了异常动态库.
// 比如通过DYLD_INSERT_LIBRARIES注入动态库。
// list all dylibs linked by my application.
// if jailbroken, there should be like "Library/MobileSubstrate/MobileSubstrate.dylib".
inline int check_dylibs(void) __attribute__((always_inline));
int check_dylibs(void)
{
    int status = 0;
    
    const char* evilLibs[] =  { "Substrate", "cycript"}; // should not be allowed
    const char* xcodeKeywords[] = {"Xcode", "iPhoneSimulator" };    // warning
    
    printf("check dyld image list: ");

  // get count of all currently loaded DYLD
  uint32_t count = _dyld_image_count();
  for (uint32_t i = 0 ; i < count; ++i)
  {
    //Name of image (includes full path)
    const char *dyld = _dyld_get_image_name(i);  // do we need to free ?
    //printf("%s\n",  dyld);

    //Get name of file without path
    char name[256] = {0};
    {
      int slength = strlen(dyld);
      int j;
      for (j = slength - 1; j >= 0; --j) {
        if (dyld[j] == '/') break;
      }
      j++;
      strncpy(name, dyld + j, slength - j);
      //printf("%s\n", name);
    }


    // check if it is injected by any
    for ( int x = 0; x < sizeof(evilLibs) / sizeof(char*); x++)
    {
      if ( strstr(dyld, evilLibs[x]) != NULL )
      {
        printf("%s shown in image %s!\n", evilLibs[x], dyld);
          status = status | 1;
          set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_DYLIBS);
          break;
        //return 1;
      }
    }
      
      // check if it is for used by simulator
      for ( int x = 0; x < sizeof(xcodeKeywords) / sizeof(char*); x++)
      {
          if ( strstr(dyld, xcodeKeywords[x]) != NULL )
          {
              printf("%s shown in image %s!\n", xcodeKeywords[x], dyld);
              status = status | 2;
              set_simulator_status(THREAT_SIMULATOR_XCODE);
              set_debugger_status(THREAT_DEBUGGER_XCODE);
              break;
              //return 1;
          }
      }
      
      if ( status > 0 )
      {
          break;
      }

  }

    printf( status == 0 ? "OK\n": "Fail\n");
    return status;
}





// MobileSubstrate uses environment variable "DYLD_INSERT_LIBRARIES" to inject its dylib.
// getenv = /Library/MobileSubstrate/MobileSubstrate.dylib
// however
// Xcode is capable of inserting its own library for debugging purpose.
// with Xcode
// getenv = /Developer/usr/lib/libBacktraceRecording.dylib:/Developer/Library/PrivateFrameworks/DTDDISupport.framework/libViewDebuggerSupport.dylib
int check_env(void)
{
    int status = 0;
    
    printf("check environment: ");
    
  char *env = getenv("DYLD_INSERT_LIBRARIES");
  if ( env == NULL)
  {
    printf("OK\n");
    return 0; // normal
  }

    printf("found DYLD_INSERT_LIBRARIES: %s\n", env);

  // skip check for xcode debug purpose
  if ( strstr(env, "/Developer/") == env )
  {
    printf("for Xcode developer, %s\n", env);
    status = status | 2;
      set_debugger_status(THREAT_DEBUGGER_XCODE);
    return 0;
  }

  if ( strstr(env, "MobileSubstrate") != NULL )
  {
      // jailbroken by MobileSubstrate
    // this one we are quite sure it is jailbroken
    printf("found DYLD_INSERT_LIBRARIES: %s\n", env);
      status = 1;
      set_root_jailbreak_status(THREAT_JAILBREAK_ENV_DYLD_INSERT_LIBS);
    //return 1;
  }


  return status;
}

// system() - Calling the system() function with a NULL argument
// on a device in jail will return 0; doing the same on a jailbroken device will return 1.
// This is since the function will check whether /bin/sh exists,
// and this is only the case on jailbroken devices.
// See https://developer.apple.com/library/ios/documentation/System/Conceptual/ManPages_iPhoneOS/man3/system.3.html
// return:  0 OK, 1 jailbroken
int check_system_command(void)
{
    int ret = system(NULL);
    if ( ret != 0 )
    {
        printf("sh found by system command. jailbroken.\n");
        set_root_jailbreak_status(THREAT_JAILBREAK_SYSTEM_COMMAND);
        return 1;
    }
    
    return 0;
}



#define IOS_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define IOS_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define IOS_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define IOS_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define IOS_VERSION_LESS_THAN_OR_EQUAL_TO(v)     ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)


// Page Execution Check
// On iOS devices running iOS 4.3.3 and lower,
// pages of memory cannot be marked as executable unless a device’s kernel has been jailbroken.
// iOS 4.3.3及以前版本可以作为是否越狱的判断标准，这倒可以作为内核完整性校验
// 如果内核验证是完整的, vm_protect function should fail
// Warning: 新的iOS已改. OBSOLETE
// 来源:  book "Hacking and Securing iOS Applications"
// 如何使用vm_protect来patch内存，请参考: MAC OS X 内存Patch 也疯狂
// http://www.dllhook.com/post/21.html

#include <mach/mach_init.h> 
#include <mach/vm_map.h> 
#include <sys/stat.h>

#include <UIKit/UIKit.h>

int check_page_execution(void)
{
    if (IOS_VERSION_GREATER_THAN(@"4.3.3"))
    {
        return 0;
    }
    
    
    void *mem = malloc(getpagesize() + 15);
    if (!mem) return 0;
    
    void *ptr = (void *)(((uintptr_t)mem+15) & ~ 0x0F);

    vm_address_t pagePtr = (uintptr_t)ptr / getpagesize() * getpagesize();
    
    mach_port_t port = mach_task_self();

    kern_return_t err;
    err = vm_protect(port, pagePtr, getpagesize(), FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    
    free(mem);
    
    // The call to the vm_protect function should fail if the kernel’s integrity is intact
    int is_jailbroken = (err == 0); //  KERN_SUCCESS = 0
    if (is_jailbroken)
    {
        set_root_jailbreak_status(THREAT_JAILBREAK_PAGE_EXECUTION);
    }
    
    return is_jailbroken;
}





// overall jailbreak and simulator check
// return:  0 OK, 1 jailbroken, 2 simulator, 3= 1+2
int check_jailbreak(void)
{
    check_cydia();
    check_fstab_file();
    is_linkfile_existed();
    check_fork();
    check_hooked_function();
    check_dylibs();
    check_env();
    check_system_command();
    check_page_execution();
    
    uint32_t status = get_root_jailbreak_status();

    return (status != 0);
}
