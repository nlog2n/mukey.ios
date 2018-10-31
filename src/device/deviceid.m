
#include <Foundation/Foundation.h>


#include "deviceid.h"
#include "crypto/mu_hash.h"



NSString* NSString_mac_addr(unsigned char *macAddress)
{
    // Read from char array into a string object, into traditional Mac address format
    NSString *macAddressString = [NSString stringWithFormat:@"%02X:%02X:%02X:%02X:%02X:%02X",
                                  macAddress[0], macAddress[1], macAddress[2],
                                  macAddress[3], macAddress[4], macAddress[5]];
    //NSLog(@"Mac: %@", macAddressString);
    return macAddressString;
}

void print_mac_addr(unsigned char *macAddress)
{
    printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           macAddress[0], macAddress[1], macAddress[2],
           macAddress[3], macAddress[4], macAddress[5]);
}


NSString* print_device_info(struct device_info*  pDevice)
{
    /*
    printf("hw machine: %s\n", pDevice->hw_machine);
    printf("hw model  : %s\n", pDevice->hw_model);
    
    printf("uname sysname : %s\n", pDevice->uname_sysname);
    printf("uname machine : %s\n", pDevice->uname_machine);
    
    printf("uidevice model: %s\n", pDevice->uidevice_model);
    printf("uidevice localizedModel: %s\n", pDevice->uidevice_localizedModel);
    printf("uidevice systemName: %s\n", pDevice->uidevice_systemName);

    printf("screen scale : %d\n", pDevice->screen_scale);
    printf("screen width : %d\n", pDevice->screen_width);
    printf("screen height: %d\n", pDevice->screen_height);
    
    printf("keychain uuid: %s\n", pDevice->keychain_uuid);
    */
    

    NSString *hw_machine     = [NSString stringWithFormat:@"machine: %s\n", pDevice->hw_machine];
    NSString *hw_model       = [NSString stringWithFormat:@"model: %s\n", pDevice->hw_model];
    NSString *hw_cpu         = [NSString stringWithFormat:@"cpu: %s\n", pDevice->hw_cpu];
    NSString *hw_ncpu        = [NSString stringWithFormat:@"cpu num: %d\n", pDevice->hw_ncpu];

    NSString *cpu_frequency  = [NSString stringWithFormat:@"cpu frequency: %d\n", pDevice->cpu_frequency];
    NSString *bus_frequency  = [NSString stringWithFormat:@"bus frequency: %d\n", pDevice->bus_frequency];
    
    NSString *hw_byteorder   = [NSString stringWithFormat:@"byte order: %d\n", pDevice->hw_byteorder];
    
    
    NSString *hw_physmem    = [NSString stringWithFormat:@"phy memsize: %d\n", pDevice->hw_physmem];
    NSString *hw_usermem    = [NSString stringWithFormat:@"user memsize: %d\n", pDevice->hw_usermem];
    NSString *hw_memsize    = [NSString stringWithFormat:@"mem size: %d\n", pDevice->hw_memsize];
    NSString *hw_pagesize    = [NSString stringWithFormat:@"page size: %d\n", pDevice->hw_pagesize];
    NSString *hw_cachelinesize    = [NSString stringWithFormat:@"cachelinesize: %d\n", pDevice->hw_cachelinesize];
    NSString *hw_l1icachesize    = [NSString stringWithFormat:@"l1icachesize: %d\n", pDevice->hw_l1icachesize];
    NSString *hw_l1dcachesize    = [NSString stringWithFormat:@"l1dcachesize: %d\n", pDevice->hw_l1dcachesize];
    NSString *hw_l2settings    = [NSString stringWithFormat:@"l2settings: %d\n", pDevice->hw_l2settings];
    NSString *hw_l2cachesize    = [NSString stringWithFormat:@"l2cachesize: %d\n", pDevice->hw_l2cachesize];
    NSString *hw_tbfrequency    = [NSString stringWithFormat:@"tbfrequency: %d\n", pDevice->hw_tbfrequency];
    
    
    
    
    NSString *uname_sysname  = [NSString stringWithFormat:@"uname sysname : %s\n", pDevice->uname_sysname];
    NSString *uname_machine  = [NSString stringWithFormat:@"uname machine : %s\n", pDevice->uname_machine];


    
    
    NSString *uidevice_model = [NSString stringWithFormat:@"uidevice model: %s\n", pDevice->uidevice_model];
    NSString *uidevice_localmodel = [NSString stringWithFormat:@"uidevice localizedModel: %s\n", pDevice->uidevice_localizedModel];
    NSString *uidevice_sysname = [NSString stringWithFormat:@"uidevice systemName: %s\n", pDevice->uidevice_systemName];
    NSString *uidevice_sysversion = [NSString stringWithFormat:@"uidevice systemVersion: %s\n", pDevice->uidevice_systemVersion];
    NSString *uidevice_vendorid = [NSString stringWithFormat:@"uidevice idforvendor: %s\n", pDevice->uidevice_identifierForVendor];
    
    
    NSString *screen_scale   = [NSString stringWithFormat:@"screen scale : %d\n", pDevice->screen_scale];
    NSString *screen_width   = [NSString stringWithFormat:@"screen width : %d\n", pDevice->screen_width];
    NSString *screen_height  = [NSString stringWithFormat:@"screen height: %d\n", pDevice->screen_height];
    NSString *keychain_uuid  = [NSString stringWithFormat:@"keychain uuid: %s\n", pDevice->keychain_uuid];

    NSString *mu_udid        = [NSString stringWithFormat:@"mu udid: %s\n", pDevice->mu_udid];
    
    
    NSString *mac_addr1      = [NSString stringWithFormat:@"mac address1: %@\n", NSString_mac_addr(pDevice->mac_address1)];
    NSString *mac_addr2      = [NSString stringWithFormat:@"mac address2: %@\n", NSString_mac_addr(pDevice->mac_address2)];
    
    NSString *carrier_name     = [NSString stringWithFormat:@"carrier name: %s\n", pDevice->carrier_name];
    NSString *network_type     = [NSString stringWithFormat:@"network type: %s\n", pDevice->network_type];
    NSString *signal_strength  = [NSString stringWithFormat:@"signal level: %d\n", pDevice->signal_strength];
    NSString *phone_number     = [NSString stringWithFormat:@"phone number: %s\n", pDevice->phone_number];
    
    
    NSString *bundle_name    = [NSString stringWithFormat:@"bundle name:  %s\n", pDevice->app_bundle_name];
    NSString *platform_name  = [NSString stringWithFormat:@"platform name:  %s\n", pDevice->app_platform_name];
    NSString *bundle_identifier  = [NSString stringWithFormat:@"bundle identifier:  %s\n", pDevice->app_bundle_identifier];
    
    
    NSString *battery_id    = [NSString stringWithFormat:@"battery id:  %s\n", pDevice->battery_id];
    NSString *mlb_serial_number    = [NSString stringWithFormat:@"mlb serial number:  %s\n", pDevice->mlb_serial_number];
    NSString *unique_chip_id    = [NSString stringWithFormat:@"chip id:  %s\n", pDevice->unique_chip_id];
    NSString *die_id    = [NSString stringWithFormat:@"die id:  %s\n", pDevice->die_id];
    NSString *gyro_temp_table    = [NSString stringWithFormat:@"gyro temp table:  %s\n", pDevice->gyro_temp_table];
    NSString *gyro_interrupt_calibration    = [NSString stringWithFormat:@"gyro interrupt calibration:  %s\n", pDevice->gyro_interrupt_calibration];
    NSString *low_temp_accel_offset    = [NSString stringWithFormat:@"low temp accel offset:  %s\n", pDevice->low_temp_accel_offset];
    NSString *lcd_panel_id    = [NSString stringWithFormat:@"lcd panel id:  %s\n", pDevice->lcd_panel_id];
    NSString *device_imei    = [NSString stringWithFormat:@"device imei:  %s\n", pDevice->device_imei];
    NSString *serial_number    = [NSString stringWithFormat:@"serial number:  %s\n", pDevice->serial_number];
    NSString *backlight_level   = [NSString stringWithFormat:@"backlight level:  %s\n", pDevice->backlight_level];
    
    

    NSString *io_platform_name    = [NSString stringWithFormat:@"io platform name:  %s\n", pDevice->platform_name];
    NSString *bluetooth_mac    = [NSString stringWithFormat:@"bluetooth mac:  %s\n", pDevice->bluetooth_mac];
    NSString *wifi_mac1    = [NSString stringWithFormat:@"wifi mac1:  %s\n", pDevice->wifi_mac1];
    NSString *wifi_mac2    = [NSString stringWithFormat:@"wifi mac2:  %s\n", pDevice->wifi_mac2];
    
    
    
    
    NSString *IOPlatformUUID    = [NSString stringWithFormat:@"platform uuid:  %s\n", pDevice->IOPlatformUUID];
    NSString *IOPlatformSerialNumber    = [NSString stringWithFormat:@"platform serial num:  %s\n", pDevice->IOPlatformSerialNumber];
    
    
    NSString *deviceInfoString = [NSString stringWithFormat:@"Device Info:\n%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@\n",
                           hw_machine, hw_model,
                           hw_cpu, hw_ncpu, cpu_frequency, bus_frequency,
                           hw_byteorder,
                           hw_physmem, hw_usermem, hw_memsize, hw_pagesize,
                           hw_cachelinesize, hw_l1icachesize, hw_l1dcachesize, hw_l2settings, hw_l2cachesize, hw_tbfrequency,
                           uname_sysname, uname_machine,
                           uidevice_model, uidevice_localmodel, uidevice_sysname, uidevice_sysversion, uidevice_vendorid,
                           screen_scale, screen_width, screen_height,
                           carrier_name, network_type, signal_strength, phone_number,
                           keychain_uuid, mu_udid,
                           mac_addr1, mac_addr2,
                           bundle_name, platform_name, bundle_identifier,
                           battery_id, mlb_serial_number, unique_chip_id, die_id,
                           gyro_temp_table, gyro_interrupt_calibration, low_temp_accel_offset, lcd_panel_id,
                           device_imei, serial_number, backlight_level,
                           io_platform_name, bluetooth_mac, wifi_mac1, wifi_mac2,
                           IOPlatformUUID, IOPlatformSerialNumber
                        ];
    
    return deviceInfoString;
}


// 从设备中提取信息
int  extract_device_info(struct device_info *pDeviceInfo)
{
    if (!pDeviceInfo) return 0; // fail
    
    memset(pDeviceInfo, 0, sizeof(struct device_info));
    
    get_sysctl_hw_info(pDeviceInfo);
    
    get_uname_info(pDeviceInfo);
    
    get_uidevice_info(pDeviceInfo);
    

    
    
    // other device info which is not for device identifier,but for status verification
    
    // get wifi mac address
    unsigned char macAddress1[6];
    get_mac_addr(macAddress1);

    unsigned char macAddress2[6];
    get_mac_addr2(macAddress2);
    
    memcpy(pDeviceInfo->mac_address1, macAddress1, 6);
    memcpy(pDeviceInfo->mac_address2, macAddress2, 6);


    get_app_info(pDeviceInfo);
    
    get_iokit_infos(pDeviceInfo);
    get_iokit_extension_infos();
    
    
    get_telephony_info(pDeviceInfo);
    get_telephony_info_2(pDeviceInfo);


    create_or_get_my_UUID(pDeviceInfo);
    
    
    //  输出以前格式的DFP信息
    get_legacy_dfp();
    
    return 1; // OK
}


// 生成设备指纹，以20字节Hash形式
unsigned char*  get_device_fingerprint(struct device_info *pDeviceInfo)
{
    static unsigned char hash[20] = {0};
    
    if (!pDeviceInfo) return hash;
    
    // 计算SHA1 Hash
    mu_sha1(pDeviceInfo,sizeof(pDeviceInfo), hash);
    
    return hash;
}



NSString* show_device_info(void)
{
    // extract device info
    struct device_info deviceInfo;
    extract_device_info(&deviceInfo);

    // get device finger print
    unsigned char* hash = get_device_fingerprint(&deviceInfo);

    // print out
    NSString *deviceInfoString = print_device_info(&deviceInfo);
    
    NSMutableString *hashString = [NSMutableString string];
    for (int i = 0; i < 20; i++)
    {
        //  printf("%02x", hash[i]);
        [hashString appendFormat:@"%02x", hash[i]];
    }
    hashString = [hashString uppercaseString];
    
    
    NSString* result = [NSString stringWithFormat:@"%@\nDFP: %@", deviceInfoString, hashString];
    
    return result;
}