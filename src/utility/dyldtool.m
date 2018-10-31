#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>

#include "dyldtool.h"


// read file to buffer, starting from offset with count size
static ssize_t read_file(int f, unsigned char *buf, size_t offset, size_t count)
{
    if (lseek(f, offset, SEEK_SET) < 0)
        return -1;

    return read(f, buf, count);
}

// 读image file, 并返回指定architecture在文件中的偏移量
// read the offset to the target mach-o in image file
// input :   file descriptor, and cpu type, and cpu subtype
// return: offset for fat binary
//         0      for non fat binary
//         -1     for error
static off_t read_head_offset(int descriptor, int cputype, int cpusubtype)
{
    uint32_t magic;

    uint32_t nfat_arch, i;
    struct fat_arch const *fat_archs = 0;
    struct fat_arch const *fat_arch_i;

    if (read(descriptor, &magic, sizeof(uint32_t)) != sizeof(uint32_t))
        return -1;

    //if only one architecture, 则偏移量为0
    if (magic == MH_MAGIC_ARCH_DEPENDENT)
        return 0;

    magic = OSSwapInt32(magic);

    // if fat binary
    if (magic == FAT_MAGIC)
    {
        if (read(descriptor, &nfat_arch, sizeof(uint32_t)) != sizeof(uint32_t))
            return -1;

        nfat_arch = OSSwapInt32(nfat_arch);
        unsigned char buf[nfat_arch * sizeof(struct fat_arch)];

        ssize_t len = read_file(descriptor, buf, sizeof(struct fat_header), nfat_arch * sizeof(struct fat_arch));
        fat_archs = (struct fat_arch const *)buf;

        if (len == -1)
            return -1;

        for (fat_arch_i = fat_archs, i = 0; i < nfat_arch; ++fat_arch_i, ++i)
        {
            cpu_type_t cpu_type = fat_arch_i->cputype;
            cpu_type = OSSwapInt32(cpu_type);

            //if (cpu_type == CPU_TYPE_ARM || cpu_type == CPU_TYPE_ARM64)
            if (cpu_type == cputype)
            {
                cpu_subtype_t cpu_subtype = fat_arch_i->cpusubtype;
                cpu_subtype = OSSwapInt32(cpu_subtype);
                if (cpu_subtype == cpusubtype)
                    return OSSwapInt32(fat_arch_i->offset);
            }
            /*
            else if ( cpu_type == CPU_TYPE_X86 || cpu_type == CPU_TYPE_X86_64 )
            {
                // for simulator
            }
            else
            {
                // not allowed
            }
            */

        }
    }
    return -1;
}



// 尝试从单个文件中读取dylib的指定字节to buffer
// extract code-section of the library either from physical file
// input:    指定范围 [offset, offset+count]
// return:   allocated buffer containing bytes
// note:     必需手动释放内存
unsigned char* extract_image_bytes_from_file(const char* dli_fname,
                                             int cputype, int cpusubtype,
                                             off_t dataoff, size_t datasize)
{
    // int fd = open(dli_fname, O_RDONLY);
    int fd = syscall(SYS_open, dli_fname, O_RDONLY);
    if ( fd == -1 )
    {
        printf("open file %s error\n", dli_fname);
        return 0;  // fail
    }
    
    off_t head_offset = read_head_offset(fd, cputype, cpusubtype);
    if (head_offset == -1)
    {
        printf("invalid head_offset\n");
        close(fd);
        return 0;
    }
    printf("image %s is valid with cpu header: %d-%d.\n", dli_fname, cputype, cpusubtype);
    
    unsigned char *data = (unsigned char*) malloc(datasize);
    if (!data)
    {
        close(fd);
        return 0;
    }
    
    if ( read_file(fd, data, head_offset + dataoff, datasize) == -1 )
    {
        free(data);
        close(fd);
        return 0;
    }
    
    close(fd);
    return data;
}





// 从mac header读取内存中code segment->code section的起始地址和大小，不重新分配内存
unsigned char* read_image_code_section(mach_header_t* header,  size_t *outLen, off_t *outOffset)
{
    // parse the image header to get offset and size of code-section of the library
    intptr_t offset = 0;
    uint32_t size = 0;
    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    segment_command_t *cur_segment;
    for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_segment->cmdsize)
    {
        cur_segment = (segment_command_t *)cur;
        if (cur_segment->cmd == LC_SEGMENT_ARCH_DEPENDENT && strcmp(cur_segment->segname, SEG_TEXT) == 0)
        {
            for (uint j = 0; j < cur_segment->nsects; j++)
            {
                section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
                if (strcmp(sect->sectname, SECT_TEXT) == 0)
                {
                    offset = sect->addr - cur_segment->vmaddr;
                    size = sect->size;
                    break;
                }
            }
            break;
        }
    }
    
    if (size == 0)
    {
        // code section not found
        printf("text section not found.\n");
        *outLen = 0;
        return 0;
    }
    
    
    //printf("\tcpusubtype: 0x%X\n", (uint32_t)header->cpusubtype);
    //printf("\toffset: 0x%X\n\tsize = %d bytes\n", (uint32_t) offset, (uint32_t) size);
    
    // read bytes directly from memory
    unsigned char *mem = (unsigned char *) ((off_t)header + offset);
    *outLen = size;
    *outOffset = offset;
    printf("text section: addr = 0x%X, size = %d bytes\n", (uint32_t)mem, (uint32_t)size);
    return mem;
}







// read code signature into a buffer
// input:  image header
// output: buffer
// return: length, or -1 for LC_CODE_SIGNATURE not found, etc errors.
unsigned char* read_image_code_signature(mach_header_t* header,  size_t *outLen)
{
    *outLen = 0;
    
    // Step 1: 获取dyld image header中code signature信息
    
    // TODO: 判断 image_header->cpusubtype 是否是simulator
    
    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    load_command_t *cur_ld_cmd = NULL;
    linkedit_data_command_t *code_sig_cmd = NULL;
    
    //find offset and size of code-section of the library
    for (uint i = 0; i < header->ncmds; i++, cur += cur_ld_cmd->cmdsize)
    {
        cur_ld_cmd = (load_command_t *)cur;
        if (cur_ld_cmd->cmd == LC_CODE_SIGNATURE)
        {
            code_sig_cmd = (linkedit_data_command_t *)cur;
            break;
        }
    }
    
    if (code_sig_cmd == NULL)
    {
        printf("warning: LC_CODE_SIGNATURE section missing\n");
        return 0;
    }
    
    
    // Step 2: 读取image file内容到缓存
    Dl_info info;
    if ( dladdr(header, &info) == 0 )
    {
        printf("cannot get image info\n");
        return 0;
    }
    
    char imgpath[PATH_MAX+1];
    realpath(info.dli_fname, imgpath);
    unsigned char* data = extract_image_bytes_from_file(imgpath,
                                                        header->cputype,
                                                        header->cpusubtype,
                                                        code_sig_cmd->dataoff,
                                                        code_sig_cmd->datasize);
    if (!data)
    {
        return 0;
    }
    
    *outLen = code_sig_cmd->datasize; // buffer len
    return data;
}



// 检查dyld image是否包含 fairplay encryption
// return:  1 - encrypted, 0-no encryption, including LC_ENCRYPTION_INFO not found
int read_image_encryption_info(mach_header_t* header)
{
    struct load_command *cmd = (struct load_command *) (header+1);
    for (uint32_t j = 0; cmd != NULL && j < header->ncmds; j++)
    {
        // Encryption info segment
        if (cmd->cmd == LC_ENCRYPTION_INFO || cmd->cmd == LC_ENCRYPTION_INFO_64)
        {
            struct encryption_info_command *crypt_cmd = (struct encryption_info_command *) cmd;
            // Check if binary encryption is enabled
            if (crypt_cmd->cryptid == 0)
            {
                // Disabled, probably pirated
                printf("cryptid = 0 (not encrypted)\n");
                return 0;
            }
            else {
                // regarded as OK
                printf("cryptid = 1 (encrypted)\n");
                return 1;
            }
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }
    
    // Encryption info not found. usually this wont happen
    printf("warning: LC_ENCRYPTION_INFO section missing\n");
    return 0; // LC_ENCRYPTION_INFO not found
}




int main (int argc, char *argv[]);

mach_header_t* get_my_image_header()
{
    // 取第一个loaded dyld image的certificate
    // 但是有时应用并不是第一个image, 比如在xcode载入时.
    // return check_image_code_signature(0, cert);
    
    
    // 另一种方法
    mach_header_t *header;
    Dl_info dlinfo;
    
    // Fetch the dlinfo for main()
    if (dladdr(main, &dlinfo) == 0 || dlinfo.dli_fbase == NULL)
    {
        printf("could not find main() symbol, it is odd.\n");
        return 0;  // regarded as abnormal
    }
    
    header = (mach_header_t*) dlinfo.dli_fbase;
    return header;
}

