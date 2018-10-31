#ifndef __MUKEY_DEVICE_ID_H__
#define __MUKEY_DEVICE_ID_H__

#include <Foundation/Foundation.h>

// used to generate device finger print
struct device_info {
    
    ////////////////////////////////// from sysctl
    char  hw_machine[32];     // string
    char  hw_model[32];       // string
    char  hw_cpu[256];        // string, not available for iOS
    int   hw_ncpu;
    int   hw_byteorder;
    int   hw_physmem;
    int   hw_usermem;
    int   hw_memsize;
    int   hw_pagesize;       // 4096
    int   hw_cachelinesize;
    int   hw_l1icachesize;
    int   hw_l1dcachesize;
    int   hw_l2settings;
    int   hw_l2cachesize;
    int   hw_tbfrequency;
    
    int   cpu_frequency;
    int   bus_frequency;
    ///////////////////////////////// from sysctl end
    
    
    
    
    char  uname_sysname[32];   // from uname, string
    char  uname_machine[32];   // from uname, string
    
    char  uidevice_model[32];           // from UIDevice, string
    char  uidevice_localizedModel[32];  // from UIDevice, string
    char  uidevice_systemName[32];      // from UIDevice, string
    
    int   screen_scale;  // from UIDevice
    int   screen_width;  // from UIDevice
    int   screen_height; // from UIDevice
    
    char  keychain_uuid[128];    // from KeyChain, string

    //////////////////////////////////////////// private API, 可能被发现不能上AppStore
    unsigned char battery_id[100];                // from IOKit,
    unsigned char mlb_serial_number[100];         // from IOKit
    unsigned char unique_chip_id[20];             // from IOKit
    unsigned char die_id[20];                     // from IOKit

    unsigned char gyro_temp_table[100];
    unsigned char gyro_interrupt_calibration[100];
    unsigned char low_temp_accel_offset[100];
    unsigned char lcd_panel_id[100];
    
    unsigned char device_imei[100];
    unsigned char serial_number[100];
    unsigned char backlight_level[100];
    
    
    unsigned char platform_name[100];   // string
    unsigned char bluetooth_mac[32];
    unsigned char wifi_mac1[32];
    unsigned char wifi_mac2[32];
    

    unsigned char IOPlatformUUID[100];            // from IOKit
    unsigned char IOPlatformSerialNumber[100];    // from IOKit
    ////////////////////////////////////////// private API end.
    
    
    
    ///////////////////////////////////////////////
    // 以下信息在同一设备上也可能会改变，不作为生成DFP的因子
    
    char uidevice_systemVersion[32];      // from UIDevice, string
    char uidevice_identifierForVendor[128];  // from UIDevice, string
    
    char mu_udid[128];    // create my own UDID by setting NSUserDefaults key
    
    unsigned char mac_address1[6];  // 因iOS高版本不支持
    unsigned char mac_address2[6];
    
    // 用到了private API.
    int  signal_strength;      // 用户可能会更换电信运营商
    char carrier_name[64];
    char network_type[64];
    char phone_number[64];  // string
    
    // APP 相关信息，可能移到app status更合适
    char app_bundle_name[128];  // from mainBundle, string
    char app_platform_name[128];   // from mainBundle, string
    char app_bundle_identifier[128];  // from mainBundle, string
    
    
};



struct mukey_device_profile{
    uint32_t   device_id;
};


#ifdef __cplusplus
extern "C" {
#endif
    
    void get_sysctl_hw_info(struct device_info* pDevice);
    void get_uname_info(struct device_info* pDevice);
    void get_uidevice_info(struct device_info* pDevice);
    
    //int get_memory_size();
    
    int get_mac_addr(unsigned char *macAddress);
    int get_mac_addr2(unsigned char *macAddress);
    
    void create_or_get_my_UUID(struct device_info* pDeviceInfo);
        
    void get_telephony_info(struct device_info *pDeviceInfo);
    void get_telephony_info_2(struct device_info *pDeviceInfo);
    
    void get_app_info(struct device_info* pDeviceInfo);
    
    void get_iokit_infos(struct device_info* pDeviceInfo);
    int get_iokit_extension_infos();
    
    void get_legacy_dfp();
    
    NSString* show_device_info(void);
    
#ifdef __cplusplus
}
#endif

#endif


