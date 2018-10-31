#import <stdio.h>
#import <stdlib.h>
#import <string.h>

#import <dlfcn.h>
#import <unistd.h>
#import <fcntl.h>

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/fat.h>

#import <sys/types.h>
#import <sys/stat.h>
#import <sys/mman.h>

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>

#include "utility/dyldtool.h"
#include "profile/appstatus.h"


// validate function source
// iOS 检查函数指针是否在指定库文件(dylib)内， 类似于Android/Linux检查

int validate_function_source(const char* func_name, const char* lib_name)
{
	// 找到函数指针
	void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);
	void *func_ptr =   dlsym(handle, func_name);
	if (!func_ptr)
	{
		dlclose(handle);
		return 0;
	}

	// search by image name
	const char* image_name = NULL;
	mach_header_t* image_header = 0;
	for (uint32_t idx = 0; idx < _dyld_image_count(); idx++)
	{
		image_name    = _dyld_get_image_name(idx);
		if (strcmp(image_name, lib_name) == 0)
		{
			// 找到指定库地址
			image_header = (mach_header_t*) (unsigned long) _dyld_get_image_header(idx);
			break;
		}
	}
	if (!image_header)
	{
		dlclose(handle);
		return 0;
	}

    // 获得image code section 地址范围
    size_t code_size = 0;
    off_t  offset = 0;
    unsigned char* mem = read_image_code_section(image_header,  &code_size, &offset);
    if (!mem)
    {
        dlclose(handle);
        return 0;
    }

    // 检查函数地址是否在指定范围内, 之前只是检查是否小于header地址.
	if ( !(   (unsigned long)func_ptr >= (unsigned long)mem
           && (unsigned long)func_ptr <  (unsigned long)(mem+code_size) ))
	{
		printf("threat: func %s not in lib %s!\n", func_name, lib_name);
        dlclose(handle);
        set_func_tampered_status();
		return 1; // tampered
	}


    // 查找关于函数指针更多信息, for debug
    /*
	Dl_info info;
	if (!dladdr(func_ptr, &info))
	{
		printf("could not dl info find %s!\n", func_name);
		dlclose(handle);
		return 0;
	}

    // 再一次检查库文件路径名
    if (  strcmp(info.dli_fname, lib_name) != 0 || strcmp(info.dli_sname, func_name) != 0 )
    {
        dlclose(handle);
        printf("warning: func %s %s was renamed to %s %s\n", func_name, lib_name, info.dli_sname, info.dli_fname);
        // set_func_tampered_status();
        return 0;
    }
    */
    
    
	dlclose(handle);
	return 0;
}




// 函数和库文件的包含关系:
// 这几个可能是需要重点检查的库文件.
// 指定函数名和所在库文件名
// system C 函数集合
#define libsystem_c_dylib_cstr               "/usr/lib/system/libsystem_c.dylib"
#define sysctl_cstr                          "sysctl"
#define time_cstr                            "time"
#define strstr_cstr                          "strstr"

#define strcmp_cstr                          "strcmp"
#define malloc_cstr                          "malloc"


// strcmp 在 iOS 7.0及以上的名字和库
#define libsystem_platform_dylib_cstr        "/usr/lib/system/libsystem_platform.dylib"
#define _platform_strcmp_cstr                "_platform_strcmp"

// malloc 新iOS版本在库libsystem_malloc.dylib中
#define libsystem_malloc_dylib_cstr          "/usr/lib/system/libsystem_malloc.dylib"



// dyld C 函数集合
#define libdyld_dylib_cstr                   "/usr/lib/system/libdyld.dylib"
#define dladdr_cstr                          "dladdr"
#define dlclose_cstr                         "dlclose"
#define dlopen_cstr                          "dlopen"
#define dlsym_cstr                           "dlsym"





// IOKit Obj-C 函数集合
#define IOKitPath                   "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
#define IOServiceGetMatchingService_cstr     "IOServiceGetMatchingService"
#define IOServiceMatching_cstr               "IOServiceMatching"
#define IORegistryEntryCreateCFProperty_cstr "IORegistryEntryCreateCFProperty"
#define IORegistryEntrySearchCFProperty_cstr "IORegistryEntrySearchCFProperty"
#define IOObjectRelease_cstr                 "IOObjectRelease"



// 更多函数也可参考 fishhook_check.m 中定义的要检测的函数列表.




// API
int validate_function_pointers()
{
    int hooked = 0;
    
    printf("checking function pointers...\n");

	hooked = hooked || validate_function_source(sysctl_cstr, libsystem_c_dylib_cstr);
	hooked = hooked || validate_function_source(time_cstr,   libsystem_c_dylib_cstr);
    hooked = hooked || validate_function_source(strstr_cstr, libsystem_c_dylib_cstr);
    
    // 实测发现iOS7 and above，函数 "strcmp" 不在 "/usr/lib/system/libsystem_c.dylib" 库中，
    // 而在"/usr/lib/system/libsystem_platform.dylib"中.
    // 并且 strcmp 和 _platform_strcmp 的函数地址一样.
    // 再利用dl info回查发现函数名和库名改为: "_platform_strcmp", "/usr/lib/system/libsystem_platform.dylib"
    // Note: 用后者一对查询还是OK.
    if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 7.0)
    {
        hooked = hooked || validate_function_source(strcmp_cstr, libsystem_platform_dylib_cstr);
        hooked = hooked || validate_function_source(_platform_strcmp_cstr, libsystem_platform_dylib_cstr);
        
        hooked = hooked || validate_function_source(malloc_cstr, libsystem_malloc_dylib_cstr);
    }
    else
    {
        hooked = hooked || validate_function_source(strcmp_cstr, libsystem_c_dylib_cstr);
        hooked = hooked || validate_function_source(malloc_cstr, libsystem_c_dylib_cstr);
    }
    
    
    hooked = hooked || validate_function_source(dladdr_cstr,  libdyld_dylib_cstr);
    hooked = hooked || validate_function_source(dlclose_cstr, libdyld_dylib_cstr);
    hooked = hooked || validate_function_source(dlopen_cstr,  libdyld_dylib_cstr);
    hooked = hooked || validate_function_source(dlsym_cstr,   libdyld_dylib_cstr);
    
    hooked = hooked || validate_function_source(IOServiceGetMatchingService_cstr,     IOKitPath);
    hooked = hooked || validate_function_source(IOServiceMatching_cstr,               IOKitPath);
    hooked = hooked || validate_function_source(IORegistryEntryCreateCFProperty_cstr, IOKitPath);
    hooked = hooked || validate_function_source(IORegistryEntrySearchCFProperty_cstr, IOKitPath);
    hooked = hooked || validate_function_source(IOObjectRelease_cstr,                 IOKitPath);
    
    printf("checking function pointers end.\n");
    
	return hooked;
}