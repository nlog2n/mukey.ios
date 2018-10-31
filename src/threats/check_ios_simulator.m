#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>

#include "check_ios_simulator.h"
#include "utility/dyldtool.h"
#include "profile/appstatus.h"


// check simulator in run-time by querying UIDevice
void check_simulator_uidevice(void)
{
    UIDevice *deviceInfo = [UIDevice currentDevice];
    // deviceInfo.name
    
    // Available Properties in UIDevice
    // uniqueIdentifier – identifier guaranteed to be unique for every device
    // name – arbitrary name found in General > About setting on device
    // systemName – name of the OS running on the device
    // systemVersion – current version of the OS
    // model- model, such as ”iPhone” or ”iPod touch”
    // localizedModel – same as above using a localized string
    
    
    // model: No longer works on Simulator for iOS9, but works for ios8 and below
    // in Xcode 7, iOS 9 Simulator [[UIDevice currentDevice] model] is returning iPhone also instead of iPhone Simulator.
	NSString *model = [[UIDevice currentDevice] model];
    // only care about "simulator" in general, not iPhone or iPad in particular
    NSLog(@"model: %@", model);
	if ( [model hasSuffix:@"Simulator"] )
    // if ([model isEqualToString:@"iPhone Simulator"])
	{
        printf("found simulator by device model.\n");
        set_simulator_status(STATUS_SIMULATOR_UIDEVICE_MODEL);
		//return 1; // device is simulator
	}

    // In iOS9, check the device name instead of model. works for ios 8, 9
    NSString *name = [[UIDevice currentDevice] name];
     NSLog(@"name: %@", name);
    if ( [name hasSuffix:@"Simulator"] )
	{
		//Code executing on Simulator
        printf("found simulator by device name.\n");
        set_simulator_status(STATUS_SIMULATOR_UIDEVICE_NAME);
		//return 1;
	}

	// works for ios 8, 9
    NSDictionary *environment = [ [NSProcessInfo processInfo] environment ];
     NSLog(@"processinfo environment: %@", environment);
    if ( [ environment objectForKey:@"SIMULATOR_DEVICE_NAME"] != nil )
	{
        printf("found simulator by process info.\n");
        set_simulator_status(STATUS_SIMULATOR_PROCESSINFO_EVN);
		//return 1;
	}

	return; // running on device
}


// 判断本程序是否运行在simulator中.
// 查看自己的binary header是否targeted for x86_64 architecture
// 参考: dyldtool.m中函数read_head_offset()
int check_simulator_x86_image(void)
{
    mach_header_t* header = get_my_image_header();
    if (!header)
    {
        printf("=>could not find app image.\n");
        return 0; // error, but return OK
    }

    // can get header->cpusubtype;
    // uint32_t magic = header->magic;
    cpu_type_t    cputype = header->cputype;
    //cputype = OSSwapInt32(cputype);
    if (cputype == CPU_TYPE_ARM || cputype == CPU_TYPE_ARM64)
    {
        // on ARM, for real device
        return 0;
    }
    else // if ( cputype == CPU_TYPE_X86 || cputype == CPU_TYPE_X86_64 )
    {
        // for simulator
        set_simulator_status(STATUS_SIMULATOR_X86_IMAGE);
        return 1;
    }

    return 0;
}



// "hw.cputype" 可以判断simulator吗? 可能新iOS版本被禁止了? 还未验证.
//  参考:  device_info.m get_sysctl_hw_info()
#include <sys/types.h>
#include <sys/sysctl.h>
int check_simulator_cputype()
{
    size_t size;
    
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
    
    size = sizeof(cpu_type);
    if ( sysctlbyname("hw.cputype", &cpu_type, &size, NULL, 0) == 0 ) // success
    {
        if  (cpu_type == CPU_TYPE_X86 || cpu_type == CPU_TYPE_X86_64)
        {
            set_simulator_status(STATUS_SIMULATOR_HW_CPUTYPE);
            return 1;
        }
    }
    
    size = sizeof(cpu_subtype);
    if ( sysctlbyname("hw.cpusubtype", &cpu_subtype, &size, NULL, 0) == 0 ) // success
    {
        
    }
    
    return 0;
}


///////////////////////////

#include <mach/mach_host.h>
int check_simulator_host_info()
{
    host_basic_info_data_t hostInfo;
    mach_msg_type_number_t infoCount;
    
    infoCount = HOST_BASIC_INFO_COUNT;
    host_info(mach_host_self(), HOST_BASIC_INFO, (host_info_t)&hostInfo, &infoCount);
    
    if (hostInfo.cpu_type == CPU_TYPE_ARM || hostInfo.cpu_type == CPU_TYPE_ARM64)
    {
        // ARM 32 or 64-bit CPU
        return 0;
    }
    else {
        // Something else.
        set_simulator_status(STATUS_SIMULATOR_HOSTINFO);
        return 1;
    }
}



// API
void check_simulator(void)
{
    check_simulator_uidevice();
    check_simulator_x86_image();
    check_simulator_cputype();
    check_simulator_host_info();
}

