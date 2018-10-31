#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>


@import Foundation;
@import UIKit;
@import CoreLocation;


#include "utility/dyldtool.h"
#include "profile/appstatus.h"


// 如何检查一个obj-c函数被替换, 以UDID spoof为例:
// 假设 UDID_func_ptr在库 a.dylib中，首先检查载入的库, 以名字找到该库并获取地址(_dyld_get_image_header(i)).
// 然后用obj-c method: sel_registerName(string)找到该 func ptr (IMP).
// 最后比较  function_ptr 是否在 [ dylib_start_address,  dylib_end_address] 中。
// 由于只有起始地址，所以只比较:   function_ptr >= dylib_start_address.
// 不符合的则认为函数在别处实现，有被hooked or tampered.

// 另一种方法是 use "dladdr" to parse funcptr_UDID to get library path，然后检查路径。


// Note that uniqueIdentifer as private API has long been deprecated by Apple since iOS 7.
// That means using sel_registerName to get the UDID is not always supported by Apple.


// references:
// Detect UDID spoofing on the iPhone at runtime
//    http://stackoverflow.com/questions/4165138/detect-udid-spoofing-on-the-iphone-at-runtime

//udid spoof further check
// 检查系统库是否被替换/hooked
// 检查系统函数的地址是否在指定库文件中
int check_system_dylibs(void)
{
    // Note that UDID implementation has been moved from UIKit to other place (/usr/lib/libobjc.A.dylib).
#define uniqueIdentifier_cstr                               "uniqueIdentifier"
#define UDID_library_for_ios_9_0_and_below                  "/System/Library/Frameworks/UIKit.framework/UIKit"
#define UDID_library_for_ios_9_2                            "/usr/lib/libobjc.A.dylib"
    
    int result = 0;

    const char* udid_dylib_name = NULL;
    unsigned long udid_dylib_addr = 0;

    // 比较 UDID获取函数的地址是否在指定库文件中
    // Usage: [UIDevice uniqueIdentifier]
    IMP funcptr_UDID = [UIDevice instanceMethodForSelector:sel_registerName(uniqueIdentifier_cstr)];

    // get image where function resides
    Dl_info info;
    if ( dladdr(funcptr_UDID, &info) != 0 )  // success
    {
        printf("image path: %s\n", info.dli_fname);
        printf("image base: 0x%X\n", (uint32_t)info.dli_fbase);

        udid_dylib_addr = (unsigned long)info.dli_fbase;
        udid_dylib_name = info.dli_fname;
    }
    else
    {
        printf("dladdr udid function failed.\n");
        return 1;
    }

    // check name
    if (udid_dylib_name == NULL)
    {
        printf("dladdr: null udid image name\n");
        return 2;  // null image name
    }
    if ( strcmp(udid_dylib_name, UDID_library_for_ios_9_0_and_below) != 0 
        && strcmp(udid_dylib_name, UDID_library_for_ios_9_2) != 0 )
    {
        printf("dladdr: image name mismatch.\n");
        return 3; // image name mismatch
    }

    // 利用该image name查找库
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++)
    {
        const char* name = (char *)_dyld_get_image_name(i);
        if (!strcmp(name, udid_dylib_name))
        {
            printf("found loaded dylib for udid.\n");
            udid_dylib_addr = (unsigned long)(_dyld_get_image_header(i));
        }
    }

    if ( udid_dylib_addr != 0 )
    if ( (unsigned long)funcptr_UDID < udid_dylib_addr)
    {
        printf("UDID method hooked: udid func=0x%X, uikit addr=0x%X\n", (uint32_t)funcptr_UDID, (uint32_t)udid_dylib_addr);
        result = 4;
    }

    return result;
}




int check_system_dylibs_2(void)
{
    int result = 0;
    
#define SystemLibFrameworkUIKit              "/System/Library/Frameworks/UIKit.framework/UIKit"
#define SystemLibFrameworkFoundation    	 "/System/Library/Frameworks/Foundation.framework/Foundation"
#define SystemLibFrameworkCorelocation		 "/System/Library/Frameworks/CoreLocation.framework/CoreLocation"
#define SystemLibFrameworkCoreFoundation	 "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
#define SystemLibPrivateFrameworkiTunesStore "/System/Library/PrivateFrameworks/iTunesStore.framework/iTunesStore"
    
    unsigned long uikit_loc = 0;
    unsigned long foundation_loc=0;
    unsigned long corelocation_loc=0;
    unsigned long corefoundation_loc=0;
    unsigned long itunesstore_loc=0;
    
    //look for uikit & foundation in libraries
    uint32_t count=_dyld_image_count();
    for (uint32_t i=0; i<count; i++)
    {
        const char *name=_dyld_get_image_name(i);
        unsigned long loc = (unsigned long)(_dyld_get_image_header(i));
        
        if (!strcmp(name,SystemLibFrameworkUIKit))
        {
            uikit_loc= loc;
        }
        if (!strcmp(name,SystemLibFrameworkFoundation))
        {
            foundation_loc= loc;
        }
        if (!strcmp(name,SystemLibFrameworkCorelocation))
        {
            corelocation_loc= loc;
        }
        if (!strcmp(name,SystemLibFrameworkCoreFoundation))
        {
            corefoundation_loc= loc;
        }
        if (!strcmp(name,SystemLibPrivateFrameworkiTunesStore))
        {
            itunesstore_loc= loc;
        }
    }
    
    //file operation hooked
    #define kNSFileManager                  @"NSFileManager"
    Class NSFileManager=NSClassFromString(kNSFileManager);
    IMP funcptr_NSFM_1=[NSFileManager instanceMethodForSelector:@selector(fileExistsAtPath:isDirectory:)];
    IMP funcptr_NSFM_2=[NSFileManager instanceMethodForSelector:@selector(fileExistsAtPath:)];
    if ((unsigned long)funcptr_NSFM_1 < foundation_loc || (unsigned long)funcptr_NSFM_2 < foundation_loc)
    {
        printf("NSFileManager method hooked: 0x%X 0x%X\n",(uint32_t)funcptr_NSFM_1, (uint32_t)funcptr_NSFM_2);
        result = 1;
    }
    
    //location spoofers
#define kCLLocationManager              @"CLLocationManager"
#define kCLLocation                     @"CLLocation"
    Class CLLocationManager = NSClassFromString(kCLLocationManager);
    Class CLLocation = NSClassFromString(kCLLocation);
    IMP funcptr_CLLocationManager_location = [CLLocationManager instanceMethodForSelector:@selector(location)];
    IMP funcptr_CLLocation_coordinate = [CLLocation instanceMethodForSelector:@selector(coordinate)];
    if (((unsigned long)funcptr_CLLocationManager_location < corelocation_loc)
        || ((unsigned long)funcptr_CLLocation_coordinate < corelocation_loc))
    {
        printf("location spoofed: location or coordinate.\n");
        result = 2;
    }
    
    
    //screen captures
     #define kUIWindow                       @"UIWindow"
    Class UIWindow = NSClassFromString(kUIWindow);
    IMP funcptr_UIWindow_sendEvent = [UIWindow instanceMethodForSelector:@selector(sendEvent:)];
    if ((unsigned long)funcptr_UIWindow_sendEvent < uikit_loc)
    {
        printf("screen captured: UIWindow sendEvent.\n");
        result = 3;
    }
    
    
    // 检查是否有三类键盘钩子: UIKeyboardImpl, NSNotificationCenter, UITextField/ UIWebFormDelegate
    //keyloggers: UIKeyboardImpl hook
    Class UIKeyboardImpl=NSClassFromString(@"UIKeyboardImpl");
    IMP funcptr_KB_insert=[UIKeyboardImpl instanceMethodForSelector:@selector(callShouldInsertText:)];
    IMP funcptr_KB_delete=[UIKeyboardImpl instanceMethodForSelector:@selector(deleteBackwardAndNotify:)];
    IMP funcptr_KB_clear=[UIKeyboardImpl instanceMethodForSelector:@selector(clearInput)];
    IMP funcptr_KB_setTraits=[UIKeyboardImpl instanceMethodForSelector:@selector(setDefaultTextInputTraits:)];
    if (   ((unsigned long)funcptr_KB_insert < uikit_loc) || ((unsigned long)funcptr_KB_delete < uikit_loc)
        || ((unsigned long)funcptr_KB_clear  < uikit_loc) || ((unsigned long)funcptr_KB_setTraits < uikit_loc))
    {
        printf("keyboard hooked. UIKeyboardImpl.\n");
        result = 7;
        
        set_keylogger_status(THREAT_KEYBOARD_HOOK_UIKeyboardImpl);
    }
    
    // keyloggers: NSNotificationCenter hook
    Class NSNotificationCenter = NSClassFromString(@"NSNotificationCenter");
    IMP funcptr_NSNotif = [NSNotificationCenter instanceMethodForSelector:@selector(postNotificationName:object:userInfo:)];
    if ((unsigned long)funcptr_NSNotif < foundation_loc)
    {
        printf("keyboard hooked: NSNotificationCenter.\n");
        result = 8;
        
        set_keylogger_status(THREAT_KEYBOARD_HOOK_NSNotificationCenter);
    }
    
    // Keyboard Hook - UITextField/ UIWebFormDelegate
    Class UITextField = NSClassFromString(@"UITextField");
    IMP funcptr_UITextField_endedEditing = [UITextField instanceMethodForSelector:sel_registerName("_endedEditing")];
    IMP funcptr_UITextField_shouldEndEditing = [UITextField instanceMethodForSelector:sel_registerName("_shouldEndEditing")];
    IMP funcptr_UITextField_isMarkedText = [UITextField instanceMethodForSelector:sel_registerName("keyboardInput:shouldInsertText:isMarkedText:")];
  
    if (((unsigned long)funcptr_UITextField_endedEditing <  uikit_loc) ||
        ((unsigned long)funcptr_UITextField_shouldEndEditing < uikit_loc) ||
        ((unsigned long)funcptr_UITextField_isMarkedText < uikit_loc))
    {
        printf("keyboard hooked: UITextField.\n");
        result = 9;
        
        set_keylogger_status(THREAT_KEYBOARD_HOOK_UITextField);
    }
    
    Class UIWebFormDelegate = NSClassFromString(@"UIWebFormDelegate");
    IMP funcptr_UIWebFormDelegate_textFieldDidEndEditing = [UIWebFormDelegate instanceMethodForSelector:sel_registerName("textFieldDidEndEditing:inFrame:")];
    if ((unsigned long)funcptr_UIWebFormDelegate_textFieldDidEndEditing < uikit_loc)
    {
        printf("keyboard hooked: UIWebFormDelegate.\n");
        result = 10;
        
        set_keylogger_status(THREAT_KEYBOARD_HOOK_UIWebFormDelegate);
    }
    
    
    
    
    

    // anti- ios method swizzling for NSArray using flex ( https://github.com/Flipboard/FLEX )
    //runtime tampering - Flex v2
     #define kNSArray						@"NSArray"
    Class CNSArray = NSClassFromString(kNSArray);
    IMP funcptr_CNSArray_arrayByCollapsing = [CNSArray instanceMethodForSelector:@selector(arrayByCollapsing)];
    IMP funcptr_CNSArray_isSerializable = [CNSArray instanceMethodForSelector:@selector(isSerializable)];
    if (funcptr_CNSArray_arrayByCollapsing != funcptr_CNSArray_isSerializable)
    {
        if (((unsigned long)funcptr_CNSArray_arrayByCollapsing < corefoundation_loc)
            && ((unsigned long)funcptr_CNSArray_isSerializable < corefoundation_loc))
        {
            printf("runtime patching Flex 2: arrayByCollapsing isSerializable\n");
            result = 4;
        }
    }
    //runtime tampering - Flex v1
     #define kNSBundle						@"NSBundle"
    Class CNSBundle = NSClassFromString(kNSBundle);
    IMP funcptr_CNSBundle_loadAndReturnError = [CNSBundle instanceMethodForSelector:@selector(loadAndReturnError:)];
    IMP funcptr_CNSBundle_load = [CNSBundle instanceMethodForSelector:@selector(load)];
    if (((unsigned long)funcptr_CNSBundle_loadAndReturnError < foundation_loc)
        && ((unsigned long)funcptr_CNSBundle_load < foundation_loc))
    {
        printf("runtime patching Flex 1: loadAndReturnError load\n");
        result = 5;
    }
    
    //ISURLOperation - AppBuyer malware
     #define kISURLOperation					@"ISURLOperation"
    Class CISURLOperation = NSClassFromString(kISURLOperation);
    IMP funcptr_CISURLOperation_connection = [CISURLOperation instanceMethodForSelector:@selector(connectionDidFinishLoading:)];
    if (((unsigned long)funcptr_CISURLOperation_connection < itunesstore_loc))
    {
        printf("SSL connection hooked: connectionDidFinishLoading\n");
        result = 6;
    }
    
    
    return result;
}