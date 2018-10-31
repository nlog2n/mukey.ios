#include <dlfcn.h>


#include "deviceid.h"



// 获取本机的手机号码: 利用 CTSettingCopyMyPhoneNumber();  这个私有方法可以返回手机号码

// method 1:
// 导入CoreTelephony这个private framework (私有，appstore审核是不通过的)
// 标识extern NSString *CTSettingCopyMyPhoneNumber();之后就可以直接引用CTSettingCopyMyPhoneNumber()
//
// extern NSString* CTSettingCopyMyPhoneNumber();
// NSString *phone = CTSettingCopyMyPhoneNumber();

// method 2:
// 利用linux下动态库显式调用api的函数。先包含头文件 #import <dlfcn.h>

//int getSignalLevel()
void get_telephony_info(struct device_info *pDeviceInfo)
{
    //获取库句柄
    void *libHandle = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY);
    
    
    NSString* (*pCTSettingCopyMyPhoneNumber)() = dlsym(libHandle, "CTSettingCopyMyPhoneNumber");
    if (pCTSettingCopyMyPhoneNumber == nil)
    {
        printf("error: pCTSettingCopyMyPhoneNumber is nil\n");
    }
    else
    {
        NSString* ownPhoneNumber = pCTSettingCopyMyPhoneNumber();
        if (ownPhoneNumber == nil)
        {
            printf("error: null phone number.\n");  // 会跳到这里，似乎已经拿不到手机号了.
        }
        else
        {
            const char *phone_number_cstr = [ownPhoneNumber cStringUsingEncoding:NSASCIIStringEncoding];
            strncpy(pDeviceInfo->phone_number, phone_number_cstr, sizeof(pDeviceInfo->phone_number)-1);
        }
    }
    
    
    
    // 获取当前信号的强弱
    int (*CTGetSignalStrength)(); //定义一个与将要获取的函数匹配的函数指针
    CTGetSignalStrength = (int(*)())dlsym(libHandle, "CTGetSignalStrength"); //获取指定名称的函数
    if (CTGetSignalStrength == NULL)
    {
        printf("error: pCTGetSignalStrength is nil\n");
    }
    else
    {
        int level = CTGetSignalStrength();
        //printf("signal level: %d\n", level);
        pDeviceInfo->signal_strength = level;
    }
    
    dlclose(libHandle); //切记关闭库
}








// 获取运营商的信息, 这种方法可能会被App Store发现.
#import <CoreTelephony/CTCarrier.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>

void get_telephony_info_2(struct device_info *pDeviceInfo)
{
    // 创建Telephony Network对象
	CTTelephonyNetworkInfo *info = [[CTTelephonyNetworkInfo alloc] init];

    // 获取运行商的名称: carrier name
	CTCarrier *carrier = [info subscriberCellularProvider];
	NSString *mCarrier = [NSString stringWithFormat:@"%@", [carrier carrierName]];
    const char* carrier_name_cstr = [mCarrier cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDeviceInfo->carrier_name, carrier_name_cstr, sizeof(pDeviceInfo->carrier_name)-1);
    
    
    // 获取当前网络的类型: network type
    // ios7之后可以按照以下方式获取。方便而且类型多
	NSString *mNetworkType = [[NSString alloc] initWithFormat:@"%@", info.currentRadioAccessTechnology];
    const char* network_type_cstr = [mNetworkType cStringUsingEncoding:NSASCIIStringEncoding];
    strncpy(pDeviceInfo->network_type, network_type_cstr, sizeof(pDeviceInfo->network_type)-1);
    /*
	类型有以下：
	 CTRadioAccessTechnologyGPRS      	//介于2G和3G之间，也叫2.5G ,过度技术
	 CTRadioAccessTechnologyEdge       	//EDGE为GPRS到第三代移动通信的过渡，EDGE俗称2.75G
	 CTRadioAccessTechnologyWCDMA
	 CTRadioAccessTechnologyHSDPA        	//亦称为3.5G(3?G)
	 CTRadioAccessTechnologyHSUPA        	//3G到4G的过度技术
	 CTRadioAccessTechnologyCDMA1x   	//3G
	 CTRadioAccessTechnologyCDMAEVDORev0    //3G标准
	 CTRadioAccessTechnologyCDMAEVDORevA
	 CTRadioAccessTechnologyCDMAEVDORevB
	 CTRadioAccessTechnologyeHRPD     	//电信使用的一种3G到4G的演进技术， 3.75G
	 CTRadioAccessTechnologyLTE   		//接近4G
	 */
}


