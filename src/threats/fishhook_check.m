
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include <dlfcn.h>
#include <sys/types.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif


#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif


#include "profile/appstatus.h"

// fish hook detection: 检查符号表是否被篡改，类似于Linux GOT hook detection.
// About fishhook.c and fishhook.h, 参考facebook的实现

// statistics for rebindings from a symbol name to its replacement
struct rebinding_entry {
    char name[64];      // 函数名字
    void *original;     // 真正的函数指针
    void *replacement;  // 即将替换的新函数指针，用作检查字段
    
    struct rebinding_entry *next;
};

static struct rebinding_entry *rebindings_head;

// 参考fishhook.c函数prepend_rebindings()
// 分配内存给以上数据结构
static int prepend_rebinding(const char* func_name)
{
    struct rebinding_entry *new_entry = malloc(sizeof(struct rebinding_entry));
    if (!new_entry)
    {
        return -1;
    }
    
    memset(new_entry, 0, sizeof(struct rebinding_entry));
    
    strncpy(new_entry->name, func_name, 63);
    
    void* handle = dlopen(0,RTLD_GLOBAL|RTLD_NOW); //获取自身载入库handle
    new_entry->original  = dlsym(handle, func_name);
    
    new_entry->replacement = 0;
    
    new_entry->next = rebindings_head;
    rebindings_head = new_entry;
    
    return 0;
}


// 加入了统计数据
static void perform_rebinding_with_section(section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab)
{
	uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
	void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
	for (uint i = 0; i < section->size / sizeof(void *); i++) 
	{
		uint32_t symtab_index = indirect_symbol_indices[i];
		if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
			symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) 
		{
			continue;
		}

		uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
		char *symbol_name = strtab + strtab_offset;
		struct rebinding_entry *cur = rebindings_head;
		while (cur) 
		{
            // 比较函数名是否一样
            if (strlen(symbol_name) > 1 && strcmp(&symbol_name[1], cur->name) == 0)
            {
					// 这里有修改:
                    // 并不实际进行绑定，但是比较要检查的函数地址是否等同于载入地址.

					// Check if mach-o '__nl_symbol_ptr' and '__la_symbol_ptr' sections being hooked by patching
					if (cur->original != 0 && cur->original != indirect_symbol_bindings[i])
					{
                        // 地址不符，进一步判断符号表中的地址为有效函数地址。如果是则判断为真正有hook
                        Dl_info tmp;
                        if (dladdr((const void *) (indirect_symbol_bindings[i]), &tmp) != 0
                            && tmp.dli_saddr == indirect_symbol_bindings[i]) // 找到一个函数符号
                        {
                                // 确认该地址可以找得到，有效。
                                cur->replacement = indirect_symbol_bindings[i];
                                printf("fish hooked: %s %p replaced by %s %p\n", cur->name, cur->original, symbol_name, cur->replacement);
                                // set status here.
                                set_fishhook_status();
                            
                        }
                        
					}
            }
			
			cur = cur->next;
		}
	}
}

// copied from fishhook.c
// 稍微修改了facebook对这个函数处理64bit.
static void rebind_symbols_for_image(const struct mach_header *header32,
                                     intptr_t slide)
{
	Dl_info info;
	if (dladdr(header32, &info) == 0)
	{
		return;
	}
    
    // 获取以下段信息
	segment_command_t *linkedit_segment = NULL;
	section_t *lazy_symbols = NULL;
	section_t *non_lazy_symbols = NULL;
	struct symtab_command* symtab_cmd = NULL;
	struct dysymtab_command* dysymtab_cmd = NULL;
	
    // added by fanghui: 判断mac header类型
    int is_header_64_bit = (header32->magic == MH_MAGIC_64 || header32->magic == MH_CIGAM_64);
    mach_header_t* header = (mach_header_t*) header32;
    //return (is_header_64_bit ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    
    
    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    segment_command_t *cur_seg_cmd;
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize)
	{
		cur_seg_cmd = (segment_command_t *)cur;
		if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) 
		{
			if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) 
			{
				linkedit_segment = cur_seg_cmd;
				continue;
			}

			if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
                strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0
                ) 
			{
				continue;
			}
			for (uint j = 0; j < cur_seg_cmd->nsects; j++) 
			{
				section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
				if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) 
				{
					lazy_symbols = sect;
				}
				if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) 
				{
					non_lazy_symbols = sect;
				}
			}
		} 
		else if (cur_seg_cmd->cmd == LC_SYMTAB) 
		{
			symtab_cmd = (struct symtab_command*)cur_seg_cmd;
		} 
		else if (cur_seg_cmd->cmd == LC_DYSYMTAB) 
		{
			dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
		}
	}
	if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
		!dysymtab_cmd->nindirectsyms) 
	{
		return;
	}
    
	// Find base symbol/string table addresses
	uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
	nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
	char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
	
    // Get indirect symbol table (array of uint32_t indices into symbol table)
	uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);
	if (lazy_symbols) 
	{
		perform_rebinding_with_section(lazy_symbols, slide, symtab, strtab, indirect_symtab);
	}
	if (non_lazy_symbols) 
	{
		perform_rebinding_with_section(non_lazy_symbols, slide, symtab, strtab, indirect_symtab);
	}
}



// 要检查的函数
#define dladdr_cstr                          "dladdr"
#define dlclose_cstr                         "dlclose"
#define dlopen_cstr                          "dlopen"
#define dlsym_cstr                           "dlsym"
#define strcmp_cstr                          "strcmp"
#define strstr_cstr                          "strstr"
#define open_cstr                            "open"
#define close_cstr                           "close"
#define malloc_cstr                          "malloc"
#define IOServiceGetMatchingService_cstr     "IOServiceGetMatchingService"
#define IOServiceMatching_cstr               "IOServiceMatching"
#define IORegistryEntryCreateCFProperty_cstr "IORegistryEntryCreateCFProperty"
#define IORegistryEntrySearchCFProperty_cstr "IORegistryEntrySearchCFProperty"
#define IOObjectRelease_cstr                 "IOObjectRelease"



// 参考 fishhook.c 函数rebind_symbols()
// 调用以上函数进行绑定.
/*
 * For each rebinding in rebindings, rebinds references to external, indirect
 * symbols with the specified name to instead point at replacement for each
 * image in the calling process as well as for all future images that are loaded
 * by the process. If rebind_functions is called more than once, the symbols to
 * rebind are added to the existing list of rebindings, and if a given symbol
 * is rebound more than once, the later rebinding will take precedence.
 */
int fish_hook_check()
{
    printf("fish hook check start...\n");

    // 初始化要检查的函数清单
    if (!rebindings_head)
    {
	    prepend_rebinding(dlopen_cstr);
        prepend_rebinding(dladdr_cstr);
        prepend_rebinding(dlsym_cstr);
        prepend_rebinding(strcmp_cstr);
        prepend_rebinding(strstr_cstr);
        prepend_rebinding(open_cstr);
        prepend_rebinding(close_cstr);
        
        prepend_rebinding(malloc_cstr);
        prepend_rebinding(IOServiceGetMatchingService_cstr);
        prepend_rebinding(IOServiceMatching_cstr);
        prepend_rebinding(IORegistryEntryCreateCFProperty_cstr);
        prepend_rebinding(IORegistryEntrySearchCFProperty_cstr);
        prepend_rebinding(IOObjectRelease_cstr);
        
        
        // 第一次，注册callback for image additions (which is also invoked for existing images)
        _dyld_register_func_for_add_image(rebind_symbols_for_image);
    }
	else  // otherwise, just run on existing images
	{
		uint32_t c = _dyld_image_count();
		for (uint32_t i = 0; i < c; i++) 
		{
			rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
		}
	}
    
    
    // 最后检查统计数据.
    int isHook = 0;
    struct rebinding_entry *cur = rebindings_head;
    while (cur)
    {
        if (cur->replacement)
        {
            isHook += 1;
            //printf("fish hooked: %s 0x%p replaced by 0x%p\n", cur->name, cur->original, cur->replacement);
            set_fishhook_status();
        }
        
        cur = cur->next;
    }
    
    printf("fish hook check end, found %d.\n", isHook);
    return isHook;
}
