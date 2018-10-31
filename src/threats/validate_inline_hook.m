#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syslimits.h>

#include "utility/dyldtool.h"
#include "utility/dyld_decache.h"
#include "profile/appstatus.h"


// iOS inline hook detection: 检查函数库是否与指定文件的code section字节一致,否则则被篡改.
// 注意要解析dylid cache来获得系统库的code section, 因为载入库可能来自于dylib cache.
// 也参考 objc function validation 和 linux/android function validation
// 也参考: dylib 自签名
//
// 一旦检测出库篡改后，继续解析篡改地址处的函数以获得更多信息.


// 对于新版本iOS, 检查是否载入的库都来自于dyld cache;否则认为有恶意载入库?
// 这个不一定！


// build command for iPhone:
// $ clang -framework Foundation -arch armv7  validate_inline_hook_ios.m  -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk

/*
 iPhone root# ./a.out
 open /private/var/root/fanghui/./a.out successfully.
 found library /private/var/root/fanghui/./a.out in file.
 loaded library matches file
 
 found library /System/Library/Frameworks/Foundation.framework/Foundation in dyld cache.
 loaded library matches cache file
 
 found library /usr/lib/libSystem.B.dylib in dyld cache.
 loaded library matches cache file
 ...
 */



// 另注意:jailbroken iPhone 5:
// found dyld cache file: /System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7.
// checking /usr/lib/system/libsystem_c.dylib...
// text section: addr = 0x3A792910, size = 359808 bytes
// fail to open /usr/lib/system/libsystem_c.dylib.
// found library /usr/lib/system/libsystem_c.dylib in dyld cache.
// warning: inline hooked library: /usr/lib/system/libsystem_c.dylib
// inline hooked function: /usr/lib/system/libsystem_c.dylib, nlist

// 原因:
// Cydia Substrate 在 MobileLoader 中 hooks nlist() to improve its performance,
// and defines several signal handlers for safe mode.
// Note: On iOS, Substrate itself hooks nlist and "upgrades" its functionality
// to be usable in combination with ASLR and the dyld shared cache.

// 这个可用来判断是否jailbroken?



// 检查载入的dylib是否被动态篡改.
int validate_inline_hook()
{
	int isHook = 0;

    int fd_cache = get_dyld_cache_file();
    if (fd_cache == 0)
	{
		printf("unable to open dyld cache file.\n");
		return 0;  // 无法比较
	}
    
    // 逐个检查载入的dylib.
	for (int i = 0; i < _dyld_image_count(); i++)
	{
        mach_header_t *image_header = (mach_header_t*) (unsigned long)_dyld_get_image_header(i);
        
        // check image name against parsed name by dladdr
        const char *image_name =   _dyld_get_image_name(i);
        printf("\nchecking %s...\n", image_name);
        
        Dl_info info;
        if ( dladdr(image_header, &info) != 0 )  // success
        {
            if (strcmp(image_name, info.dli_fname) != 0)
            {
                printf("image path: %s is renamed to %s", info.dli_fname, image_name);
                continue;  // image name changed
            }
            //printf("fbase: 0x%X \n", (uint32_t)info.dli_fbase);  // should be same as header
            //printf("image base address: 0x%X \n", (uint32_t)header);
        }
        

		// find offset and size of code-section of the loaded library
        // 不必新分配内存，因为下面还要解析函数符号.
        size_t  count;
        off_t offset;
        unsigned char* mem = read_image_code_section(image_header,  &count, &offset);
        if (!mem)
        {
            // 没找到，无法进一步比较
            continue;
        }
        
        
        // extract code-section of the library either
        // from physical file or from dyld_shared_cache_armvX file
        // 首先尝试从单个文件中读取:  (注意:较新的iOS都是把所有dylib放在cache file中)
        // 失败则从cache file中读取
        unsigned char* disk = extract_image_bytes_from_file(info.dli_fname, image_header->cputype, image_header->cpusubtype, offset, count);
        if (!disk)
        {
            // further extract from cache file
            disk = extract_lib_bytes_from_cache(info.dli_fname, fd_cache, offset, count);
            if (!disk)
            {
			// 没找到，无法进一步比较
			continue;
            }
        }


        
        // 比较两块内存for code sections是否一致，并且因为是library code, 可以找出不一致的函数符号.
        // input:   library in memory, library file, size
        int tampered = 0;
        for (size_t n = 0; n < count; n++)
        {
                if (mem[n] != disk[n])    // 这两个library bytes已经不一样了
                {
                    // 这里在non-jailbroken ios 9.3.2 上似乎有很多误报.
                    // 原因查明: 读入了不同arch的dyld cache file.
                    printf("warning: tampered library: %s\n", info.dli_fname);

                    // 只有找到符号才算inline hooked.
                    // find the hooked function, for debug purpose
                    Dl_info tmp;
                    if(dladdr((const void *) (mem + n), &tmp) != 0 && tmp.dli_saddr != 0)  // 找到一个函数符号
                    {
                        printf("threat: inline hooked function: %s, %s\n", tmp.dli_fname, tmp.dli_sname);

                        // 进一步判断是否 "/usr/lib/system/libsystem_c.dylib", "nlist", 从而认为是jailbreak.
                        if (   strcmp(tmp.dli_fname, "/usr/lib/system/libsystem_c.dylib")==0
                            && strcmp(tmp.dli_sname, "nlist")==0 )
                        {
                            set_root_jailbreak_status(THREAT_JAILBREAK_FUNCTION_HOOKED);
                        }
                        else
                        {
                            tampered = 1;
                            isHook = 1;
                            set_inline_hook_status();
                        }
                    }
                    
                    break;
                }
        }
        
        
		free(disk);
        
        if (tampered)
		{
            break;
		}
		else
		{
			printf("loaded library matches file\n");
		}
	}

	close(fd_cache);
	return isHook;
}




#ifdef __TEST_VALIDATE_INLINE_HOOK__

int main()
{
    validate_inline_hook();
	return 0;
}

#endif
