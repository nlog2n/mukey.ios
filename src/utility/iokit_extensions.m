

// 获取以下三项硬件信息: imei, serialnumber, backlightlevel
// 参考了 "UIDevice-IOKitExtensions.m"


/*
 http://broadcast.oreilly.com/2009/04/iphone-dev-iokit---the-missing.html
 
 In Xcode, I was surprised to see that Apple didn't include IOKit header files. When I tried to 
 add #import <IOKit/IOKit.h>, the file could not be found. So I manually put together a simple 
 header file by hand, added IOKit to my frameworks and attempted to compile.
 
 As you can see from the screenshot at the top of this post, I failed to do so. Xcode complained 
 that the IOKit framework could not be found. Despite being filed as public, IOKit is apparently 
 not meant to be used by the general public. As iPhone evangelist Matt Drance tweeted, 
 "IOKit is not public on iPhone. Lack of headers and docs is rarely an oversight."
 
 In the official docs, I found a quote that described IOKit as such: "Contains interfaces used by
 the device. Do not include this framework directly." So in the end, my desire to access that IOKit 
 information was thwarted. For whatever reason, Apple has chosen to list it as a public framework 
 but the reality is that it is not.
*/


#include <Foundation/Foundation.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach_host.h>


#define kIODeviceTreePlane		"IODeviceTree"

enum {
    kIORegistryIterateRecursively	= 0x00000001,
    kIORegistryIterateParents		= 0x00000002
};


typedef mach_port_t	io_object_t;
typedef io_object_t	io_registry_entry_t;
typedef io_object_t io_service_t;
typedef char		io_name_t[128];
typedef UInt32		IOOptionBits;






// 以下函数不引入private framework则linking的时候找不到，建议动态加载库并得到函数指针.

/*

kern_return_t
IOMasterPort( mach_port_t	bootstrapPort,
             mach_port_t *	masterPort );


io_registry_entry_t
IORegistryGetRootEntry(
                       mach_port_t	masterPort );

CFTypeRef
IORegistryEntrySearchCFProperty(
								io_registry_entry_t	entry,
								const io_name_t		plane,
								CFStringRef		key,
								CFAllocatorRef		allocator,
								IOOptionBits		options );


kern_return_t   mach_port_deallocate
(ipc_space_t                               task,
 mach_port_name_t                          name);




// 从根masterPort开始查找指定名字属性
NSArray *getValue(const char* iosearch)
{
    mach_port_t          masterPort;
    CFTypeID             propID = (CFTypeID) NULL;
    unsigned int         bufSize;
	
    // 获取入口
    kern_return_t kr = IOMasterPort(MACH_PORT_NULL, &masterPort);
    if (kr != noErr) return nil;
	
    io_registry_entry_t entry = IORegistryGetRootEntry(masterPort);
    if (entry == MACH_PORT_NULL) return nil;
	
    
    // 查找IO Registry
    CFTypeRef prop = IORegistryEntrySearchCFProperty(entry, kIODeviceTreePlane,
                                                     CFStringCreateWithCString(NULL, iosearch, kCFStringEncodingMacRoman),
                                                     nil, kIORegistryIterateRecursively);
    if (!prop) return nil;
	
    // 检查数据类型, 这里只承认Data Type
	propID = CFGetTypeID(prop);
    if (!(propID == CFDataGetTypeID())) 
	{
		mach_port_deallocate(mach_task_self(), masterPort);
		return nil;
	}
    CFDataRef propData = (CFDataRef) prop;
    if (!propData) return nil;
	
    // 数据长度
    bufSize = CFDataGetLength(propData);
    if (!bufSize) return nil;
	
    // 转换成 NSString
    NSString *info = [[NSString alloc] initWithBytes:CFDataGetBytePtr(propData) length:bufSize encoding:1] ;
    
    // 关闭
    mach_port_deallocate(mach_task_self(), masterPort);
    
    return [info componentsSeparatedByString:@"\0"];
}






NSString* get_imei()
{
    NSArray *results = getValue("device-imei");
    if (results) return [results objectAtIndex:0];
    return nil;
}


NSString* get_serialnumber()
{
    NSArray *results = getValue("serial-number");
    if (results) return [results objectAtIndex:0];
    return nil;
}

NSString* get_backlightlevel()
{
    NSArray *results = getValue("backlight-level");
    if (results) return [results objectAtIndex:0];
    return nil;
}

// API
int get_iokit_extension_infos()
{
    NSString* imei = get_imei();
    NSString* serialnumber = get_serialnumber();
    NSString* backlightlevel = get_backlightlevel();
    
    NSLog(@"imei=%@\nserial number=%@\nbacklightlevel=%@\n", imei, serialnumber, backlightlevel);
    
    return 0;
}

*/






static NSString* _get_iokit_info(
                   const char* serviceName,
                   const char* identifier,
                   int identifierCategory)
{
    NSString *info = nil;
    
    void *IOKit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    if (!IOKit)
        return nil;
    
    // 从载入库中直接获取函数指针
    mach_port_t *kIOMasterPortDefault = (mach_port_t*)dlsym(IOKit, "kIOMasterPortDefault");
    CFMutableDictionaryRef (*IOServiceMatching)(const char *name) = (CFMutableDictionaryRef (*)(const char *))dlsym(IOKit, "IOServiceMatching");
    mach_port_t (*IOServiceGetMatchingService)(mach_port_t masterPort, CFDictionaryRef matching) = (mach_port_t (*)(mach_port_t, CFDictionaryRef))dlsym(IOKit, "IOServiceGetMatchingService");
    CFTypeRef (*IORegistryEntryCreateCFProperty)(mach_port_t entry, CFStringRef key, CFAllocatorRef allocator, uint32_t options) = (CFTypeRef (*)(mach_port_t, CFStringRef, CFAllocatorRef, uint32_t)) dlsym(IOKit, "IORegistryEntryCreateCFProperty");
    CFTypeRef (*IORegistryEntrySearchCFProperty)(mach_port_t entry, const io_name_t plane, CFStringRef key, CFAllocatorRef allocator, uint32_t options) = (CFTypeRef (*)(mach_port_t, const io_name_t , CFStringRef, CFAllocatorRef, uint32_t))dlsym(IOKit, "IORegistryEntrySearchCFProperty");
    kern_return_t (*IOObjectRelease)(mach_port_t object) = (kern_return_t (*)(mach_port_t))dlsym(IOKit, "IOObjectRelease");
    
    // 检查所需指针是否都有效
    if (kIOMasterPortDefault && IOServiceMatching && IOServiceGetMatchingService && IORegistryEntryCreateCFProperty
        && IORegistryEntrySearchCFProperty && IOObjectRelease)
    {
        // 决定是否从树某个节点(service)开始找，还是从根找
        if (serviceName)
        {
        
        mach_port_t entry = IOServiceGetMatchingService(*kIOMasterPortDefault, IOServiceMatching(serviceName));  // for example: "IOPlatformExpertDevice"
        if (entry)
        {
            if (identifierCategory)  // 数据类型是data
            {
                //get device info for battery-id, mib-serial, ECID, DIE-ID
                    CFTypeRef info_CF = IORegistryEntrySearchCFProperty(entry, kIODeviceTreePlane,
                                                          CFStringCreateWithCString(NULL, identifier, kCFStringEncodingMacRoman), kCFAllocatorDefault, kIORegistryIterateRecursively);
                if ((info_CF != nil) && (CFGetTypeID(info_CF) == CFDataGetTypeID()))
                {
                    info = [[NSString alloc] initWithData:[NSData dataWithBytes:CFDataGetBytePtr((CFDataRef)info_CF) length:CFDataGetLength((CFDataRef)info_CF)] encoding:NSUTF8StringEncoding];
                    CFRelease(info_CF);
                }
                else
                {
                    info = [NSString stringWithFormat:@""];
                }
            }
            else   // 数据类型是string
            {
                //get device info for platform-uuid, platform-serial (没有则创建一个键值?)
                    CFTypeRef info_CF = IORegistryEntryCreateCFProperty(entry, CFStringCreateWithCString(NULL, identifier, kCFStringEncodingMacRoman), kCFAllocatorDefault, 0);
                if ((info_CF != nil) && (CFGetTypeID(info_CF) == CFStringGetTypeID())) {
                    info = [NSString stringWithString:(__bridge NSString*)info_CF];
                    CFRelease(info_CF);
                }
            }
            IOObjectRelease(entry);
        }
        }
        else   // 这个分支有问题!
        {
            // 查找IO Registry
                CFTypeRef info_CF = IORegistryEntrySearchCFProperty(*kIOMasterPortDefault, kIODeviceTreePlane,
                                                             CFStringCreateWithCString(NULL, identifier, kCFStringEncodingMacRoman),
                                                             nil, kIORegistryIterateRecursively);

            // 检查数据类型, 这里只承认Data Type
            if (info_CF != nil)
            {
                if (CFGetTypeID(info_CF) == CFDataGetTypeID())
                {
                CFDataRef propData = (CFDataRef) info_CF;
                //if (!propData) return nil;
                
                // 数据长度
                unsigned int bufSize = CFDataGetLength(propData);
                //if (!bufSize) return nil;
                
                // 转换成 NSString
                info = [[NSString alloc] initWithBytes:CFDataGetBytePtr(propData) length:bufSize encoding:NSUTF8StringEncoding];
                
                /*
                NSArray* results = [info componentsSeparatedByString:@"\0"];
                if (results)
                    info = [results objectAtIndex:0];
                */
                
                }
                else if (CFGetTypeID(info_CF) == CFStringGetTypeID())
                {
                    info = [NSString stringWithString:(__bridge NSString*)info_CF];
                    
                }
                
                CFRelease(info_CF);
                
            }
            
            
        }
    }
    
    dlclose(IOKit);
    
    return info;
}



int get_iokit_info(unsigned char* outIOSInfo,
                                const char* serviceName,
                                const char* identifier,
                                int identifierCategory)
{
    NSString* info =  _get_iokit_info(serviceName, identifier, identifierCategory);
    
    // 输出结果
    NSString* printable_info = [NSString stringWithFormat:@"%@", info];
    memcpy(outIOSInfo, [[printable_info dataUsingEncoding:NSUTF8StringEncoding] bytes], [printable_info length]);
    
    return [printable_info length];
}




