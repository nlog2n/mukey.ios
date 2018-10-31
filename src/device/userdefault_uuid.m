#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#import <Foundation/Foundation.h>
@import Foundation;
@import UIKit;


#include "deviceid.h"



// 通过NSUserDefaults为系统创建一个随机的标示符

// 考虑到该值会随应用删除而消失，可以用来存password hash. 如果发现威胁，则删除该password hash, 并要求用户重新输入密码才能使用服务.


// IOS中NSUserDefaults用来轻量级本地数据存储
// 用NSUserDefaults存储的数据下次程序运行的时候依然存在，它把数据存储在什么地方了？如何能够清除？
// 其实它存储在应用程序内置的一个plist文件里，这个可以根据路径看到。
// 比如说这个是你的程序沙盒位置
//  /UsersLibrary/Application Support/iPhoneSimulator/4.1/Applicati*****/29788E40-AF47-45A0-8E92-3AC0F501B7F4/,
// （这个是应用程序对应在mac上的位置）
// 这个下面有/Library/Prefereces，里面有个plist文件，存储的就是你的userDefaults
// 想要删掉的话，用removeObjectForKey或者删掉沙盒，也就是你的应用程序然后重新安装。



// 从ios5开始苹果官方不支持获取UniqueIndentifier（UDID） 的方法，原先的方法不管用了。苹果官方又推出了一种新的方法，获取UUID。
// 新方法的原理为在第一次使用程序的时候用CFUUIDCreate创造一个 UUID，然后将它存到NSUserDefault中，当做以前的UDID来用就行了。
// 不过直接调用CFUUIDCreate得到的还不是一个直接的NSString,需要经过一些步骤才能转换成我们熟悉UDID形式。
// 但是这个方法有一个漏洞就是，在每次该应用重装以后，新的UUID都会改变。而且据网上资料说，UUID不能保证每次在系统升级后还能用。
// 具体的实现方法为:
void create_or_get_my_UUID(struct device_info* pDeviceInfo)
{
 
#define  MU_UDID_STR     @"MuUDID"
    
	NSString *id = [[NSUserDefaults standardUserDefaults] objectForKey:MU_UDID_STR]; 	//获取标识为"MuUDID"的值
	if(id == nil)
    {
	    // otherwise create one, and store into that place
        NSLog(@"create my own udid");
    
		if([[[UIDevice currentDevice] systemVersion] floatValue] > 6.0)
		{
            // create a new random UUID string
			NSString *identifierNumber = [[NSUUID UUID] UUIDString]; //ios 6.0 之后可以使用的api

			//保存为UUID
			[[NSUserDefaults standardUserDefaults] setObject:identifierNumber forKey:MU_UDID_STR];
			[[NSUserDefaults standardUserDefaults] synchronize];
		}
		else
		{
            // create a new random UUID string
			CFUUIDRef uuid = CFUUIDCreate(NULL);
			CFStringRef uuidString = CFUUIDCreateString(NULL, uuid); //ios6.0之前使用的api
			NSString *identifierNumber = [NSString stringWithFormat:@"%@", uuidString];

            //保存
			[[NSUserDefaults standardUserDefaults] setObject:identifierNumber forKey:MU_UDID_STR];
			[[NSUserDefaults standardUserDefaults] synchronize];
			
            // free
			CFRelease(uuidString);
			CFRelease(uuid);
		}
        
        // 再次取出该值
       id =  [[NSUserDefaults standardUserDefaults] objectForKey:MU_UDID_STR];
    }
    
    // 现在得到一个替代的UDID.
    // NSLog(@"MuUDID: %@", id);
    const char *id_cstr = [id cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDeviceInfo->mu_udid, id_cstr, sizeof(pDeviceInfo->mu_udid)-1);
}


