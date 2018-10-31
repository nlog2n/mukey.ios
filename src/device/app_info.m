#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#import <Foundation/Foundation.h>
@import Foundation;
@import UIKit;


#include "deviceid.h"



void get_uidevice_info(struct device_info* pDevice)
{
    //当前设备对象
    UIDevice *device = [UIDevice currentDevice];
    
    //获取设备的类别. for simulator it is "iPhone Simulator"
    const char *model = [device.model cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDevice->uidevice_model, model, sizeof(pDevice->uidevice_model)-1);
    
    //获取本地化model版本. for simulator it is "iPhone Simulator"
    const char *localizedModel = [device.localizedModel cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDevice->uidevice_localizedModel, localizedModel, sizeof(pDevice->uidevice_localizedModel)-1);
    
    //获取当前运行的系统
    const char *systemName = [device.systemName cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDevice->uidevice_systemName, systemName, sizeof(pDevice->uidevice_systemName)-1);

    //获取当前运行的系统版本, 不固定
    const char *systemVersion = [device.systemVersion cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDevice->uidevice_systemVersion, systemVersion, sizeof(pDevice->uidevice_systemVersion)-1);
    
    
    // 获取设备的唯一标示符 (可能会变!)
    NSString *identifierForVendor = device.identifierForVendor.UUIDString;
    //NSString *identifierForVendor = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    const char *vendor_str = [identifierForVendor cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDevice->uidevice_identifierForVendor, vendor_str, sizeof(pDevice->uidevice_identifierForVendor)-1);
    
    // 获取当前屏幕分辨率的信息
    CGFloat scale = [[UIScreen mainScreen] scale];  // 可判断是否retina if scale > 1.0
    CGRect rect   = [[UIScreen mainScreen] bounds];
    CGFloat width = rect.size.width * scale;
    CGFloat height = rect.size.height * scale;
    
    pDevice->screen_scale = scale;
    pDevice->screen_width = width;
    pDevice->screen_height = height;
}


//    IOS-获取app（程序版本号）等, 这些信息会变，不适合做device identifier, 只适合做验证
void get_app_info(struct device_info* pDeviceInfo)
{
    NSDictionary *infoDictionary = [[NSBundle mainBundle] infoDictionary];
    //CFShow((__bridge CFTypeRef)(infoDictionary));
    
    // CFBundleName, DTPlatformName, CFBundleIdentifier
    
    // app name
    NSString *app_name = [infoDictionary objectForKey:@"CFBundleName"];
    const char* app_name_cstr = [app_name cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDeviceInfo->app_bundle_name, app_name_cstr, sizeof(pDeviceInfo->app_bundle_name)-1);
    
    // app platform. for simulator, it is "iphonesimulator"
    NSString *app_platform = [infoDictionary objectForKey:@"DTPlatformName"];
    const char* app_platform_cstr = [app_platform cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDeviceInfo->app_platform_name, app_platform_cstr, sizeof(pDeviceInfo->app_platform_name)-1);
    
    // app bundle identifier, 一般作为 app ID
    NSString *app_identifier = [infoDictionary objectForKey:@"CFBundleIdentifier"];
    const char* app_identifier_cstr = [app_identifier cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDeviceInfo->app_bundle_identifier, app_identifier_cstr, sizeof(pDeviceInfo->app_bundle_identifier)-1);
    
    // 另一种读取方法:
    /*
    NSString *app_identifier = [[NSBundle mainBundle] bundleIdentifier];
    int len = [app_identifier length];
    memcpy(pDeviceInfo->app_bundle_identifier, [[app_identifier dataUsingEncoding:NSUTF8StringEncoding] bytes], len);
    */
}



