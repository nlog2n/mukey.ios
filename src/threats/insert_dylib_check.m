#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

#define IS_64_BIT(x) ((x) == MH_MAGIC_64 || (x) == MH_CIGAM_64)
#define IS_LITTLE_ENDIAN(x) ((x) == FAT_CIGAM || (x) == MH_CIGAM_64 || (x) == MH_CIGAM)
#define SWAP32(x, magic) (IS_LITTLE_ENDIAN(magic)? OSSwapInt32(x): (x))
#define SWAP64(x, magic) (IS_LITTLE_ENDIAN(magic)? OSSwapInt64(x): (x))

#include "utility/dyldtool.h"
#include "profile/appstatus.h"



// 通过LC_LOAD_DYLIB实现dylib的加载
// http://bbs.iosre.com/t/igrimace-hook-root-app/440

// https://github.com/Tyilo/insert_dylib


// An output on iOS 9

/*
lc_load_dylib: /System/Library/Frameworks/Foundation.framework/Foundation
lc_load_dylib: /usr/lib/libobjc.A.dylib
lc_load_dylib: /usr/lib/libSystem.B.dylib
lc_load_dylib: /System/Library/Frameworks/AssetsLibrary.framework/AssetsLibrary
lc_load_dylib: /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
lc_load_dylib: /System/Library/Frameworks/CoreTelephony.framework/CoreTelephony
lc_load_dylib: /System/Library/Frameworks/Photos.framework/Photos
lc_load_dylib: /System/Library/Frameworks/Security.framework/Security
lc_load_dylib: /System/Library/Frameworks/UIKit.framework/UIKit
*/

// On iOS 8.1 simulator
/*
lc_load_dylib: /System/Library/Frameworks/Foundation.framework/Foundation
lc_load_dylib: /usr/lib/libobjc.A.dylib
lc_load_dylib: /usr/lib/libSystem.dylib
lc_load_dylib: /System/Library/Frameworks/AssetsLibrary.framework/AssetsLibrary
lc_load_dylib: /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
lc_load_dylib: /System/Library/Frameworks/CoreTelephony.framework/CoreTelephony
lc_load_dylib: /System/Library/Frameworks/Photos.framework/Photos
lc_load_dylib: /System/Library/Frameworks/Security.framework/Security
lc_load_dylib: /System/Library/Frameworks/UIKit.framework/UIKit
*/


static int is_suspicious_insert_dylib(const char *dylib_path)
{
    // check prefix path string, 必需来自指定的系统目录
    if (   strstr(dylib_path,"/System/Library/Frameworks/") == dylib_path
        || strstr(dylib_path, "/usr/lib/") == dylib_path)
    {
        return 0;
    }
    
    
    // check white-list, 该名单可能不全
    /*
    if (   strcmp(dylib_path, "/usr/lib/libobjc.A.dylib") == 0
        || strcmp(dylib_path, "/usr/lib/libSystem.B.dylib") == 0
        || strcmp(dylib_path, "/usr/lib/libSystem.dylib") == 0)
    {
        return 0;
    }
    */
    
    return 1;  // suspicous
}


// 检查是否有加载的恶意第三方库.
// 这里实现参考 dyldtool.m中的函数read_encryption_info(), read_code_signature()
int insert_dylib_check(void)
{
    // 获取自身的image
    mach_header_t *header = get_my_image_header();

    // 遍历load commands.
	struct load_command *cmd = (struct load_command *) (header+1);
    for (uint32_t j = 0; cmd != NULL && j < header->ncmds; j++)
    {
        // load dylib command segment
        if (cmd->cmd == LC_LOAD_DYLIB || cmd->cmd == LC_LOAD_WEAK_DYLIB)
        {
				struct dylib_command *dylib_cmd = (struct dylib_command*) cmd; 

				union lc_str offset = dylib_cmd->dylib.name;
				char *name = &((char *)dylib_cmd)[SWAP32(offset.offset, header->magic)];
                printf("lc_load_dylib: %s\n", name);

                // 检查要载入的库路径
				if(is_suspicious_insert_dylib(name))
				{
					printf("suspicious: %s\n", name);
                    set_insert_dylib_status();
				}
        }

        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }

    return 0;
}
