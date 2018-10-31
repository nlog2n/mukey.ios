#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

//#import <Foundation/Foundation.h>
@import Foundation;
@import UIKit;


#include "utility/iokit_extensions.h"
#include "deviceid.h"



// 通过iOS private API (IOKit)来获取硬件信息，包括:
// PLATFORM_UUID, PLATFORM_SERIAL, BATTERY_ID, MIB_SERIAL, ECHIP_ID, DIE_ID.

// 使用IOKit.framework框架来实现，利用private库IOKitExtentions来实现
// 参考:  Getting the IMEI for a iDevice without linking in the IOKit
// http://stackoverflow.com/questions/15652627/getting-the-imei-for-a-idevice-without-linking-in-the-iokit


// 测试结果:
//  iPhone 5S, ios 9, non-jailbreak             iPhone 4, iOS 7, jailbreak
//        battery id:       OK                  OK
//        mlb serial:       null                OK
//        chip id:          null                null
//        die id:           null                null
//        platform uuid:    null                OK
//        platform serial:  null                OK
//
//        gyro temp table:  null                null
//        gyro interrupt :  null                null
//        low temp accel:   null                null
//        lcd panel id:     null                null
//
//        device imei:      null                null
//        serial num:       null                OK  (equal to platform serial above)
//        backlight level:  null                OK
//        io platform name: null                null
//        bluetooth mac:    null                null
//        wifi mac1:        null                null
//        wifi mac2:        null                null



// 获取iOS device硬件信息

// 参考: iphone_dataprotection/ramdisk_tools/registry.c

// libmobilegestalt.dylib

// https://github.com/Gojohnnyboi/restored_pwn
 
// http://iphonedevwiki.net/index.php/Lockdownd








#define battery_id_cstr                      "battery-id"
#define mlb_serial_number_cstr               "mlb-serial-number"
#define unique_chip_id_cstr                  "unique-chip-id"
#define die_id_cstr                          "die-id"
#define gyro_temp_table_cstr                 "gyro-temp-table"
#define gyro_interrupt_calibration_cstr      "gyro-interrupt-calibration"
#define low_temp_accel_offset_cstr           "low-temp-accel-offset"
#define lcd_panel_id_cstr                    "lcd-panel-id"
#define device_imei_cstr                     "device-imei"
#define serial_number_cstr                   "serial-number"
#define backlight_level_cstr                 "backlight-level"


void get_iokit_infos(struct device_info* pDeviceInfo)
{
    int length;
    
    // Battery ID
    unsigned char batteryId[100] =  {0};
    length = get_iokit_info(batteryId, "IOPlatformExpertDevice", "battery-id", 1);
    memcpy(pDeviceInfo->battery_id, batteryId, sizeof(pDeviceInfo->battery_id));
    
    // MLB(main logic board) serial number
    unsigned char mlbSerial[100] = {0};
    length = get_iokit_info(mlbSerial, "IOPlatformExpertDevice", "mlb-serial-number", 1);
    memcpy(pDeviceInfo->mlb_serial_number, mlbSerial, sizeof(pDeviceInfo->mlb_serial_number));
    
    //ECID is unavailable since iOS 7
    unsigned char eChipId[20] = {0};  // 通常是长19
    length = get_iokit_info(eChipId, "IOPlatformExpertDevice", "unique-chip-id", 1);
    memcpy(pDeviceInfo->unique_chip_id, eChipId, sizeof(pDeviceInfo->unique_chip_id));
    
    //DIE_ID is unavailable since iOS 7
    unsigned char dieId[20] = {0};  // 通常是长19?
    length = get_iokit_info(dieId, "IOPlatformExpertDevice", "die-id", 1);
    memcpy(pDeviceInfo->die_id, dieId, sizeof(pDeviceInfo->die_id));
    
    
    // gyro-temp-table
    unsigned char gyro_temp_table[100] = {0};
    length = get_iokit_info(gyro_temp_table, "IOPlatformExpertDevice", "gyro-temp-table", 1);
    memcpy(pDeviceInfo->gyro_temp_table, gyro_temp_table, sizeof(pDeviceInfo->gyro_temp_table));
    
    
    // gyro-interrupt-calibration
    unsigned char gyro_interrupt_calibration[100] = {0};
    length = get_iokit_info(gyro_interrupt_calibration, "IOPlatformExpertDevice", "gyro-interrupt-calibration", 1);
    memcpy(pDeviceInfo->gyro_interrupt_calibration, gyro_interrupt_calibration, sizeof(pDeviceInfo->gyro_interrupt_calibration));
    
    // low-temp-accel-offset
    unsigned char low_temp_accel_offset[100] = {0};
    length = get_iokit_info(low_temp_accel_offset, "IOPlatformExpertDevice", "low-temp-accel-offset", 1);
    memcpy(pDeviceInfo->low_temp_accel_offset, low_temp_accel_offset, sizeof(pDeviceInfo->low_temp_accel_offset));
    
    // lcd-panel-id
    unsigned char lcd_panel_id[100] = {0};
    length = get_iokit_info(lcd_panel_id, "IOPlatformExpertDevice", "lcd-panel-id", 1);
    memcpy(pDeviceInfo->lcd_panel_id, lcd_panel_id, sizeof(pDeviceInfo->lcd_panel_id));
    
    
    // platform-name
    unsigned char platform_name[100] = {0};
    length = get_iokit_info(platform_name, "IOPlatformExpertDevice", "platform-name", 0);  // string type
    memcpy(pDeviceInfo->platform_name, platform_name, sizeof(pDeviceInfo->platform_name));
    
    // bluetooth MAC address
    unsigned char bluetooth_mac[32] = {0};
    length = get_iokit_info(bluetooth_mac, "bluetooth", "local-mac-address", 1);   // data
    memcpy(pDeviceInfo->bluetooth_mac, bluetooth_mac, sizeof(pDeviceInfo->bluetooth_mac));
    
    // Wifi Mac Address
    unsigned char wifi_mac1[32] = {0};
    length = get_iokit_info(wifi_mac1, "sdio", "local-mac-address", 1);
    memcpy(pDeviceInfo->wifi_mac1, wifi_mac1, sizeof(pDeviceInfo->wifi_mac1));
    
    // Wifi Mac Address, 两个一样, 如上找不到，则继续找这个
    unsigned char wifi_mac2[32] = {0};
    length = get_iokit_info(wifi_mac2, "wlan", "local-mac-address", 1);
    memcpy(pDeviceInfo->wifi_mac2, wifi_mac2, sizeof(pDeviceInfo->wifi_mac2));
    

    
    // device-imei
    unsigned char device_imei[100] = {0};
    length = get_iokit_info(device_imei, "baseband", "device-imei", 1);      // unavailable
    memcpy(pDeviceInfo->device_imei, device_imei, sizeof(pDeviceInfo->device_imei));
    
    // serial-number
    unsigned char serial_number[100] = {0};
    length = get_iokit_info(serial_number, "IOPlatformExpertDevice", "serial-number", 1);   // OK
    memcpy(pDeviceInfo->serial_number, serial_number, sizeof(pDeviceInfo->serial_number));
    
    // backlight-level
    unsigned char backlight_level[100] = {0};
    length = get_iokit_info(backlight_level, "IOPlatformExpertDevice", "backlight-level", 1);   // OK
    memcpy(pDeviceInfo->backlight_level, backlight_level, sizeof(pDeviceInfo->backlight_level));
    
    
    // UUID
    unsigned char UUID[100] = {0};
    length = get_iokit_info(UUID, "IOPlatformExpertDevice", "IOPlatformUUID", 0);  // OK
    memcpy(pDeviceInfo->IOPlatformUUID, UUID, sizeof(pDeviceInfo->IOPlatformUUID));
    
    // Serial Number
    unsigned char platformSerial[100] = {0};
    length = get_iokit_info(platformSerial, "IOPlatformExpertDevice", "IOPlatformSerialNumber", 0);   // OK
    memcpy(pDeviceInfo->IOPlatformSerialNumber, platformSerial, sizeof(pDeviceInfo->IOPlatformSerialNumber));
}





// 注意: 从根部查找似乎有些问题!
int get_iokit_extension_infos()
{
    int length;
    
    unsigned char device_imei[100] = {0};
    length = get_iokit_info(device_imei, 0, "device-imei", 1);
    
    unsigned char serial_number[100] = {0};
    length = get_iokit_info(serial_number, 0, "serial-number", 1);
    
    unsigned char backlight_level[100] = {0};
    length = get_iokit_info(backlight_level, 0, "backlight-level", 1);
    
    printf("imei=%s\nserial number=%s\nbacklightlevel=%s\n", device_imei, serial_number, backlight_level);
    
    return 0;
}







// legacy for generating IOS device finger print

#define APP_ID_LEN						64
#define PLATFORM_UUID_LEN				36
#define PLATFORM_SERIAL_LEN				12
#define BATTERY_ID_LEN					73
#define MLB_SERIAL_LEN					73
#define CHIP_ID_LEN 					19
#define DIE_ID_LEN						19

#include "crypto/mu_hash.h"

void get_legacy_dfp()
{
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    
    // [ APP_ID, PLATFORM_UUID, PLATFORM_SERIAL, BATTERY_ID, MIB_SERIAL, ECHIP_ID, DIE_ID ]
    // 每个都是字符串形式，最后一个是结束字符.
    char APP_ID[APP_ID_LEN+1] = {0};
    char PLATFORM_UUID[PLATFORM_UUID_LEN+1] = {0};
    char PLATFORM_SERIAL[PLATFORM_SERIAL_LEN+1] = {0};
    char BATTERY_ID[BATTERY_ID_LEN+1] = {0};
    char MLB_SERIAL[MLB_SERIAL_LEN+1] = {0};
    char CHIP_ID[CHIP_ID_LEN+1] = {0};
    char DIE_ID[DIE_ID_LEN+1] = {0};


    // bundle identifier as APP_ID
    {
     NSString *app_identifier = [[NSBundle mainBundle] bundleIdentifier];
     int len = [app_identifier length];
     memcpy(APP_ID, [[app_identifier dataUsingEncoding:NSUTF8StringEncoding] bytes], len);
     if (len < 64) {
        for (int i=len; i< 64; i++) {
            APP_ID[i] = '0';
        }
    }
    len = 64;
    APP_ID[len] = 0;
    }

    
    // Platform UUID
    {
    unsigned char UUID[100] = {0};
    int length = get_iokit_info(UUID, "IOPlatformExpertDevice", "IOPlatformUUID", 0);
    memcpy(PLATFORM_UUID, UUID, length +1);
    }
    
    // Platform Serial
    {
    unsigned char platformSerial[100] = {0};
    int length = get_iokit_info(platformSerial, "IOPlatformExpertDevice", "IOPlatformSerialNumber", 0);
    if (length != 12) {
        for (int i=length; i< 12; i++) {
            platformSerial[i] = '0';
        }
        length = 12;
    }
    platformSerial[length] = 0;
    memcpy(PLATFORM_SERIAL, platformSerial, length+1);
    }
    
    
    // Battery ID
    {
        unsigned char batteryId[100] =  {0};
        int length = get_iokit_info(batteryId, "IOPlatformExpertDevice", "battery-id", 1);
        memcpy(BATTERY_ID, batteryId, length+1);
    }
    
    
    // MLB Serail Number
    {
        unsigned char mlbSerial[100] = {0};
        int length = get_iokit_info(mlbSerial, "IOPlatformExpertDevice", "mlb-serial-number", 1);
        memcpy(MLB_SERIAL, mlbSerial, length+1);
    }
    
    
    // CHIP ID
    {
        unsigned char eChipId[100] = {0};  // 通常是长19
        int length = get_iokit_info(eChipId, "IOPlatformExpertDevice", "unique-chip-id", 1);
        if (length == 0) {
            length = 19;
            for (int i=0; i<length; i++) {
                eChipId[i] = '0';
            }
        }
        eChipId[length] = 0;
        memcpy(CHIP_ID, eChipId, length+1);
    }
    
    
    // DIE ID
    {
        unsigned char dieId[100] = {0};  // 通常是长19?
        int length = get_iokit_info(dieId, "IOPlatformExpertDevice", "die-id", 1);
        if (length == 0) {
            length = 19;
            for (int i=0; i<length; i++) {
                dieId[i] = '0';
            }
        }
        dieId[length] = 0;
        memcpy(DIE_ID, dieId, length+1);
    }

    
    // Summary: 拼接到一个大buffer中去
    snprintf(buffer, sizeof(buffer), "%s%s%s%s%s%s%s", APP_ID, PLATFORM_UUID, PLATFORM_SERIAL, BATTERY_ID, MLB_SERIAL, CHIP_ID, DIE_ID);
    printf("legacy device info = %s\nsize=%lu\n",buffer, strlen(buffer));


    // 计算SHA1 Hash, 20 bytes
    unsigned char hash[20] = {0};
    mu_sha1(buffer,strlen(buffer), hash);
    printf("legacy dfp:\n");
    for (int i = 0; i < 20; i++)
    {
        printf("%02x", hash[i]);
    }
    printf("\n");
}



