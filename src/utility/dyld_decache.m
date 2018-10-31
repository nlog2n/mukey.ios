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

// 解析iOS dylid cache file

// 在iOS开发中，为了提升系统的安全性，很多系统库文件都被打包到一个缓存的文件当中即dyld缓存。
// 首先，我们来了解下dyld缓存。在iOS系统中，几乎所有的程序都会用到动态库，而动态库在加载的时候
// 都需要用dyld（位于/usr/lib/dyld）程序进行链接。很多系统库几乎都是每个程序都要用到的，
// 与其在每个程序运行的时候一个一个将这些动态库都加载进来，还不如先把它们打包好，一次加载进来来的快。

// dyld缓存在系统中位于“/System/Library/Caches/com.apple.dyld/”目录下，
// 文件名是以“dyld_shared_cache_”开头，再加上这个dyld缓存文件所支持的指令集。
// 在这个目录下，有可能有多个dyld缓存文件，对应所支持的不同指令集。
// 比如，在iPad Air 2 or iPad mini 2 with iOS 9上，该目录下就存在两个缓存文件：
//
// "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
// "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7s"
//
// 因为iPad Air 2是64位的ARM（ARM v8）处理器，同时它也兼容32位的ARM应用，
// 所以就要有两个缓存文件。dyld_shared_cache_arm64对应64位的版本，而dyld_shared_cache_armv7s对应32位的版本。
// 到目前为止，所有iOS支持的ARM指令集有以下四种：
// 1) armv6
// 2) armv7
// 3) armv7s
// 4) armv7k
// 5) arm64    (fro ARMv8)
//
// iPhone 4 with iOS 7: 有一个DYLD shared cache file
// "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7"
//
// iPhone 5S with ios 9.3, 有2个cache files:
// "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7s"
// "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64"
//


// 我们还可以从dyld缓存文件中将系统库的原始二进制文件给解出来。目前，有两个工具可以做到这点，一是dyld_decache，还有一个就是jtool。
// 参考: decache
// https://github.com/phoenix3200/decache/blob/master/decache.mm


// 数据结构从decache github上copy
struct dyld_cache_header {
    char     magic[16];
    uint32_t mappingOffset;
    uint32_t mappingCount;
    uint32_t imagesOffset;
    uint32_t imagesCount;
    uint64_t dyldBaseAddress;
    
    // for v1
    /*
    uint64_t codeSignatureOffset;
    uint64_t codeSignatureSize;
    uint64_t slideInfoOffset;
    uint64_t slideInfoSize;
    uint64_t localSymbolsOffset;
    uint64_t localSymbolsSize;
    */
};
typedef struct dyld_cache_header dyld_cache_header_t;


struct dyld_cache_mapping_info { //struct shared_file_mapping_np {
    mach_vm_address_t	sfm_address;
    mach_vm_size_t		sfm_size;
    mach_vm_offset_t	sfm_file_offset;
    vm_prot_t		    sfm_max_prot;
    vm_prot_t		    sfm_init_prot;
};
typedef struct dyld_cache_mapping_info dyld_cache_mapping_info_t;




struct dyld_cache_image_info {
	uint64_t	address;
	uint64_t	modTime;
	uint64_t	inode;
	uint32_t	pathFileOffset;
	uint32_t	pad;
};
typedef struct dyld_cache_image_info dyld_cache_image_info_t;



// 获取dyld cache的路径和文件名
// 一般比如: /System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7
#define IPHONE_DYLD_SHARED_CACHE_DIR	"/System/Library/Caches/com.apple.dyld/"
#define DYLD_SHARED_CACHE_BASE_NAME		"dyld_shared_cache_"

// return: file handler for default shared dylib cache
// note: 需要手动关闭fd
int get_dyld_cache_file()
{
    // 判断当前architecture type
    mach_header_t* header = get_my_image_header();
    if (!header)
    {
        printf("=>could not find app image.\n");
        return 0; // error
    }
    
    // can get header->cpusubtype;
    // uint32_t magic = header->magic;
    cpu_type_t    cputype = header->cputype;
    if (cputype == CPU_TYPE_ARM64)
    {
        int fd_cache = open(IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "arm64", O_RDONLY);
        if (fd_cache != -1)
        {
            // close(fd);
            printf("found dyld cache file for arm64.\n");
            //fcntl(fd, F_NOCACHE, 1);
            return  fd_cache;
        }
    }
    else
    {
        const char *arch[] =
        {
        IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "i386",
        IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "x86_64",
        IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "armv5",
        IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "armv6",
        IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "armv7",
        //IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "arm64",
        IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "armv7f",
        IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "armv7k",
        IPHONE_DYLD_SHARED_CACHE_DIR DYLD_SHARED_CACHE_BASE_NAME "armv7s",
        };
    
        for (int i = 0; i < sizeof(arch) / sizeof(arch[0]); i++)
        {
            int fd_cache = open(arch[i], O_RDONLY);
            if (fd_cache != -1)
            {
            // close(fd);
            printf("found dyld cache file: %s.\n", arch[i]);
            //fcntl(fd, F_NOCACHE, 1);
            return  fd_cache;
            }
        }
        
    }
    
    return 0; // not found
}


// 从cache file中读取dylib的指定字节
// extract code-section of the library from dyld_shared_cache_armvX file
// input:    指定范围 [offset, offset+count]
// return:   allocated buffer containing bytes
// note:     必需手动释放内存
// 参考:  extract_lib_bytes_from_file
unsigned char* extract_lib_bytes_from_cache(const char* dli_fname, int fd_cache,
        off_t offset, size_t count)
{
    // read info of the images from cache file
    dyld_cache_header_t cache_header;
    pread(fd_cache, &cache_header, sizeof(cache_header), 0);
    
    dyld_cache_mapping_info_t mapping;
    pread(fd_cache, &mapping, sizeof(mapping), cache_header.mappingOffset);
    
    
    // seach in cache this library, and return starting address
    off_t startaddr  = 0;
    for (int j = 0; j < cache_header.imagesCount; j++)
    {
            // 读特定image info
            dyld_cache_image_info_t cache_image_info;
            pread(fd_cache, &cache_image_info, sizeof(cache_image_info), cache_header.imagesOffset + j * sizeof(cache_image_info));
            
            // 读 image name
            char img_name[PATH_MAX];
            pread(fd_cache, img_name, PATH_MAX, cache_image_info.pathFileOffset);
            if (strcmp(dli_fname, img_name) == 0)  // found this library
            {
                startaddr = cache_image_info.address - mapping.sfm_address;
                break;
            }
    }
    
    if (!startaddr)
    {
			printf("didnot find this library %s in cache file.\n", dli_fname);
			return 0;
    }

    // 找到该library in cache file
    printf("found library %s in dyld cache.\n", dli_fname);
	unsigned char *disk = (unsigned char *) malloc(count);
    pread(fd_cache, disk, count, startaddr + offset);
	
	return disk;
}
