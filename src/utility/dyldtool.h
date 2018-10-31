#ifndef __MUKEY_DYLD_TOOL_H__
#define __MUKEY_DYLD_TOOL_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/dyld.h>
#include <mach/machine.h>

#include <TargetConditionals.h>


// The encryption info struct and constants are missing from the
//   iPhoneSimulator SDK, but not from the iPhoneOS or Mac OS X SDKs.
//   Since one doesn't ever ship a Simulator binary, we'll just
//   provide the definitions here.
#if TARGET_IPHONE_SIMULATOR && !defined(LC_ENCRYPTION_INFO)
#define LC_ENCRYPTION_INFO 0x21
struct encryption_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
};
#endif


typedef struct load_command load_command_t;
typedef struct linkedit_data_command linkedit_data_command_t;

#ifdef __LP64__

typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#define MH_MAGIC_ARCH_DEPENDENT MH_MAGIC_64

#else

typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#define MH_MAGIC_ARCH_DEPENDENT MH_MAGIC

#endif



#ifdef __cplusplus
extern "C" {
#endif

    //ssize_t read_file(int f, unsigned char *buf, size_t offset, size_t count);
    
    //off_t read_head_offset(int descriptor, int cputype, int cpusubtype);
    
    unsigned char* extract_image_bytes_from_file(const char* dli_fname,
                                                 int cputype, int cpusubtype,
                                                 off_t dataoff, size_t datasize);
    
    unsigned char* read_image_code_section(mach_header_t* header,  size_t *outLen, off_t *outOffset);
    unsigned char* read_image_code_signature(mach_header_t* header,  size_t *outLen);
    int            read_image_encryption_info(mach_header_t* header);

    mach_header_t* get_my_image_header();    

    

#ifdef __cplusplus
}
#endif

#endif
