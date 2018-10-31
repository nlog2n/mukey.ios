#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#import <Foundation/Foundation.h>
@import Foundation;
@import UIKit;

#include "deviceid.h"



// 获取system name and machine by uname sys function
#include "sys/utsname.h"
void get_uname_info(struct device_info* pDevice)
{
    struct utsname systemInfo;   // 这是LINUX系统放硬件版本的信息的地方
    //声明结构体，包含5个char数组成员:sysname,nodename,release,version,machine
    
    //c方法，填写系统结构体内容，返回值为0，表示成功。
    if (uname(&systemInfo) != 0)
    {
        printf("error: uname(systemInfo).\n");
        return;
    }
    
    strncpy(pDevice->uname_sysname, systemInfo.sysname, sizeof(pDevice->uname_sysname) -1); // like "Darwin"
    strncpy(pDevice->uname_machine, systemInfo.machine, sizeof(pDevice->uname_machine) -1); // like "iPhone7,2"

    // uname_machine for simulator is "x86_64"
    // TODO: could be used to detect simulator.
}



#include <sys/types.h>
#include <sys/sysctl.h>
static void get_sysctl_property_string(const char* name, char* buffer, int len)
{
    size_t size;
    if (sysctlbyname(name, NULL, &size, NULL, 0) != 0)
    {
        printf("error: sysctlbyname %s get size.\n", name);
        return;
    }
    
    char *data = malloc(size);
    if (!data) return;
    
    if (sysctlbyname(name, data, &size, NULL, 0) != 0)
    {
        printf("error: sysctlbyname %s get data.\n", name);
        free(data);
        return;
    }
    
    // copy data
    memset(buffer, 0, len);
    strncpy(buffer, data, len-1);
    
    free(data);
}

static int get_sysctl_property_integer(const char* name)
{
    int result = 0;
    size_t length = sizeof(result);
    if (sysctlbyname(name, &result, &length, NULL, 0) != 0)
    {
        printf("error: sysctlbyname %s get integer value.\n", name);
        result = 0;
    }
    
    return result;
}



// cpu和总线频率
// 等价于 from $ sysctl hw.cpufrequency
int get_cpu_frequency()
{
    int                 mib[2];  // management information base
    size_t              length;
    int                 result;
    
    mib[0] = CTL_HW;
    mib[1] = HW_CPU_FREQ;
    length = sizeof(result);
    if (sysctl(mib, 2, &result, &length, NULL, 0) < 0)
    {
        printf("error: getting cpu frequency.\n");
        result = 0;
    }
    //printf("CPU Frequency = %u Hz\n", result);
    
    return result;
}


int get_bus_frequency()
{
    int                 mib[2];  // management information base
    size_t              length;
    int                 result;
    
    mib[0] = CTL_HW;
    mib[1] = HW_BUS_FREQ;
    length = sizeof(result);
    if (sysctl(mib, 2, &result, &length, NULL, 0) < 0)
    {
        printf("error: getting bus frequency.\n");
        result = 0;
    }
    //printf("Bus Frequency = %u Hz\n", result);
    
    return result;
}




// uname, sysctl "hw.machine"返回结果一样
// hw.machine example: iPhone7,2. for simulator it is "x86_64"
// Note: 但UIDevice model仅返回"iPhone".


// "hw.cputype" 可以判断simulator吗? iOS 上无此hw.cputype属性
void get_sysctl_hw_info(struct device_info* pDevice)
{
    // 例子请见 ios_sysctl_query_output.txt file
    
    get_sysctl_property_string("hw.machine", pDevice->hw_machine, sizeof(pDevice->hw_machine));
    get_sysctl_property_string("hw.model", pDevice->hw_model, sizeof(pDevice->hw_model));
    
    // cpu model, 该key只对MacOS有效，iOS上无该键值.
    //get_sysctl_property_string("machdep.cpu.brand_string", pDevice->hw_cpu, sizeof(pDevice->hw_cpu));

    pDevice->cpu_frequency = get_cpu_frequency();   // not available in iOS
    pDevice->bus_frequency = get_bus_frequency();   // not available in iOS
    
    pDevice->hw_ncpu          = get_sysctl_property_integer("hw.ncpu");
    pDevice->hw_byteorder     = get_sysctl_property_integer("hw.byteorder");
    pDevice->hw_physmem       = get_sysctl_property_integer("hw.physmem");
    pDevice->hw_usermem       = get_sysctl_property_integer("hw.usermem");
    pDevice->hw_memsize       = get_sysctl_property_integer("hw.memsize");
    pDevice->hw_pagesize      = get_sysctl_property_integer("hw.pagesize");
    
    // 4个cache size在iOS上拿不到值
    pDevice->hw_cachelinesize = get_sysctl_property_integer("hw.cachelinesize"); // unavailable
    pDevice->hw_l1icachesize  = get_sysctl_property_integer("hw.l1icachesize");  // unavailable
    pDevice->hw_l1dcachesize  = get_sysctl_property_integer("hw.l1dcachesize");  // unavailable
    pDevice->hw_l2settings    = get_sysctl_property_integer("hw.l2settings");
    pDevice->hw_l2cachesize   = get_sysctl_property_integer("hw.l2cachesize");   // unavailable
    
    pDevice->hw_tbfrequency   = get_sysctl_property_integer("hw.tbfrequency");
}



// get memory size in bytes
// 这么统计出来的大小似乎不固定! 换用 sysctlbyname("hw.memsize")
#include <mach/mach.h>
#include <mach/mach_host.h>
int get_memory_size()
{
    mach_port_t              host_port = mach_host_self();
    mach_msg_type_number_t   host_size = sizeof(vm_statistics_data_t) / sizeof(integer_t);
    vm_size_t                pagesize;
    vm_statistics_data_t     vm_stat;
    
    host_page_size(host_port, &pagesize);
    
    if (host_statistics(host_port, HOST_VM_INFO, (host_info_t)&vm_stat, &host_size) != KERN_SUCCESS)
    {
        printf("memory size: failed to fetch vm statistics\n");
        return 0;
    }
    
    natural_t   mem_used = (vm_stat.active_count + vm_stat.inactive_count + vm_stat.wire_count) * pagesize;
    natural_t   mem_free = vm_stat.free_count * pagesize;
    natural_t   mem_total = mem_used + mem_free;
    //printf("mem size in bytes =%d\n", mem_total);
    
    return mem_total;
}
