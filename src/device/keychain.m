//#import <Foundation/Foundation.h>
@import Foundation;
@import UIKit;

#import <Security/Security.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>

#include "deviceid.h"


// History

// iOS 5
// 在 iOS 5 中， 可以获取到系统的 UDID(Unique Device Identifier), or uniqueIdentifier ，
// 后来被 Apple 禁止掉了。

// iOS 6
// iOS 6.0系统新增了两个用于替换uniqueIdentifier的接口，分别是：identifierForVendor，advertisingIdentifier。
// Apple 推荐使用广告标识符 advertisingIdentifier 来获取系统的唯一标识符。
// 但是，用户如果重置了系统，广告标识符会重新生成。这就达不到 “唯一标识符” 的作用。
// 同一开发商的APP在指定机器上都会获得同一个ID。当我们删除了某一个设备上某个开发商的所有APP之后，
// 下次获取将会获取到不同的ID。” 也就是说我们通过该接口不能获取用来唯一标识设备的ID.
//
// 于是大家想到了使用WiFi的mac地址来取代已经废弃了的uniqueIdentifier方法。具体的方法晚上有很多，


// iOS 7
// MAC 地址 MAC(Medium/Media Access Control) ，后来又被 Apple 禁止掉了。
// 使用之前的方法获取到的mac地址全部都变成了02:00:00:00:00:00。
// 同样的，OpenUDID 也不能用了


// ===>  KeyChain
// 使用KeyChain来保存获取到的唯一标示符呢，这样以后即使APP删了再装回来，也可以从KeyChain中读取回来。
// 程序员们发明了 “钥匙串保存” 方法，将这个唯一标识符保存在钥匙串中，安装了 App 后读取这个标识符即可。





// 本文介绍了使用KeyChain实现APP删除后依然可以获取到相同的UDID信息的解决方法。
// 你可能有疑问，如果系统升级以后，是否仍然可以获取到之前记录的UDID数据？
// 答案是肯定的，这一点我专门做了测试。就算我们程序删除掉，系统经过升级以后再安装回来，
// 依旧可以获取到与之前一致的UDID。但是当我们把整个系统还原以后是否还能获取到之前记录的UDID，
// 这一点我觉得应该不行，不过手机里面数据太多，没有测试，如果大家有兴趣可以测试一下，验证一下我的猜想。


// 如何使用KeyChain保存和获取UDID
// http://www.cnblogs.com/smileEvday/p/UDID.html




// UDID for different iOS Version

// Note:
// before you run the project on device, you should replace "YOURAPPID" with your profile's APPID。
// the "YOURAPPID" appear in two place, one in KeyChainAccessGroup.plist, another in SvUDIDTools.m


// replace the identity with your company's domain
static const char kKeychainUDIDItemIdentifier[]  = "UUID";
static const char kKeyChainUDIDAccessGroup[] = "YOURAPPID.com.cnblogs.smileEvday";

NSString* getUDIDFromKeyChain();
BOOL settUDIDToKeyChain(NSString* udid);
BOOL removeUDIDFromKeyChain();
BOOL updateUDIDInKeyChain(NSString* newUDID);


// not yet ready
#ifdef xxxxxxxxxxx

/*
 * iOS 7.0
 * Starting from iOS 7, the system always returns the value 02:00:00:00:00:00
 * when you ask for the MAC address on any device.
 * use identifierForVendor + keyChain
 * make sure UDID consistency atfer app delete and reinstall
 */

// interface function
NSString* get_own_UDID()
{
    NSString *udid = getUDIDFromKeyChain();
    if (!udid)
    {
        // 如果没有找到（第一次），则一次性写入自己创建的ID:可能是identifierForVendor or Mac address
        // Note: 写入的时候可能需要标记类型，以便日后校验。
        NSString *sysVersion = [UIDevice currentDevice].systemVersion;
        CGFloat version = [sysVersion floatValue];
        
        if (version >= 7.0)
        {
            udid = [[UIDevice currentDevice].identifierForVendor UUIDString];
        }
        else if (version >= 2.0)
        {
            // iOS 6.0: use wifi's mac address
            unsigned char macAddress[6];
            get_mac_addr(macAddress);
            
            udid = mac_addr_nsstring(macAddress);
        }
        
        settUDIDToKeyChain(udid);
    }
    
    return udid;
}


// keychain write/read/update/remove implementations

NSString* getUDIDFromKeyChain()
{
    NSMutableDictionary *dictForQuery = [[NSMutableDictionary alloc] init];
    [dictForQuery setValue:(id)kSecClassGenericPassword forKey:(id)kSecClass];
    
    // set Attr Description for query
    [dictForQuery setValue:[NSString stringWithUTF8String:kKeychainUDIDItemIdentifier]
                    forKey:kSecAttrDescription];
    
    // set Attr Identity for query
    NSData *keychainItemID = [NSData dataWithBytes:kKeychainUDIDItemIdentifier
                                            length:strlen(kKeychainUDIDItemIdentifier)];
    [dictForQuery setObject:keychainItemID forKey:(id)kSecAttrGeneric];
    
    // The keychain access group attribute determines if this item can be shared
    // amongst multiple apps whose code signing entitlements contain the same keychain access group.
    NSString *accessGroup = [NSString stringWithUTF8String:kKeyChainUDIDAccessGroup];
    if (accessGroup != nil)
    {
#if TARGET_IPHONE_SIMULATOR
        // Ignore the access group if running on the iPhone simulator.
        //
        // Apps that are built for the simulator aren't signed, so there's no keychain access group
        // for the simulator to check. This means that all apps can see all keychain items when run
        // on the simulator.
        //
        // If a SecItem contains an access group attribute, SecItemAdd and SecItemUpdate on the
        // simulator will return -25243 (errSecNoAccessForItem).
#else
        [dictForQuery setObject:accessGroup forKey:(id)kSecAttrAccessGroup];
#endif
    }
    
    [dictForQuery setValue:(id)kCFBooleanTrue forKey:(id)kSecMatchCaseInsensitive];
    [dictForQuery setValue:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
    [dictForQuery setValue:(id)kCFBooleanTrue forKey:(id)kSecReturnData];
    
    OSStatus queryErr   = noErr;
    NSData   *udidValue = nil;
    NSString *udid      = nil;
    queryErr = SecItemCopyMatching((CFDictionaryRef)dictForQuery, (CFTypeRef*)&udidValue);
    
    NSMutableDictionary *dict = nil;
    [dictForQuery setValue:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
    queryErr = SecItemCopyMatching((CFDictionaryRef)dictForQuery, (CFTypeRef*)&dict);
    
    if (queryErr == errSecItemNotFound) {
        NSLog(@"KeyChain Item: %@ not found!!!", [NSString stringWithUTF8String:kKeychainUDIDItemIdentifier]);
    }
    else if (queryErr != errSecSuccess) {
        NSLog(@"KeyChain Item query Error!!! Error code:%ld", queryErr);
    }
    if (queryErr == errSecSuccess) {
        NSLog(@"KeyChain Item: %@", udidValue);
        
        if (udidValue) {
            udid = [NSString stringWithUTF8String:udidValue.bytes];
            [udidValue release];
        }
        [dict release];
    }
    
    [dictForQuery release];
    return udid;
}


BOOL settUDIDToKeyChain(NSString* udid)
{
    NSMutableDictionary *dictForAdd = [[NSMutableDictionary alloc] init];
    
    [dictForAdd setValue:(id)kSecClassGenericPassword forKey:(id)kSecClass];
    [dictForAdd setValue:[NSString stringWithUTF8String:kKeychainUDIDItemIdentifier] forKey:kSecAttrDescription];
    
    [dictForAdd setValue:@"UUID" forKey:(id)kSecAttrGeneric];
    
    // Default attributes for keychain item.
    [dictForAdd setObject:@"" forKey:(id)kSecAttrAccount];
    [dictForAdd setObject:@"" forKey:(id)kSecAttrLabel];
    
    
    // The keychain access group attribute determines if this item can be shared
    // amongst multiple apps whose code signing entitlements contain the same keychain access group.
    NSString *accessGroup = [NSString stringWithUTF8String:kKeyChainUDIDAccessGroup];
    if (accessGroup != nil)
    {
#if TARGET_IPHONE_SIMULATOR
        // Ignore the access group if running on the iPhone simulator.
        //
        // Apps that are built for the simulator aren't signed, so there's no keychain access group
        // for the simulator to check. This means that all apps can see all keychain items when run
        // on the simulator.
        //
        // If a SecItem contains an access group attribute, SecItemAdd and SecItemUpdate on the
        // simulator will return -25243 (errSecNoAccessForItem).
#else
        [dictForAdd setObject:accessGroup forKey:(id)kSecAttrAccessGroup];
#endif
    }
    
    const char *udidStr = [udid UTF8String];
    NSData *keyChainItemValue = [NSData dataWithBytes:udidStr length:strlen(udidStr)];
    [dictForAdd setValue:keyChainItemValue forKey:(id)kSecValueData];
    
    OSStatus writeErr = noErr;
    if (getUDIDFromKeyChain())
    {        // there is item in keychain
        updateUDIDInKeyChain(udid);
        [dictForAdd release];
        return YES;
    }
    else {          // add item to keychain
        writeErr = SecItemAdd((CFDictionaryRef)dictForAdd, NULL);
        if (writeErr != errSecSuccess) {
            NSLog(@"Add KeyChain Item Error!!! Error Code:%ld", writeErr);
            
            [dictForAdd release];
            return NO;
        }
        else {
            NSLog(@"Add KeyChain Item Success!!!");
            [dictForAdd release];
            return YES;
        }
    }
    
    [dictForAdd release];
    return NO;
}

BOOL removeUDIDFromKeyChain()
{
    NSMutableDictionary *dictToDelete = [[NSMutableDictionary alloc] init];
    
    [dictToDelete setValue:(id)kSecClassGenericPassword forKey:(id)kSecClass];
    
    NSData *keyChainItemID = [NSData dataWithBytes:kKeychainUDIDItemIdentifier length:strlen(kKeychainUDIDItemIdentifier)];
    [dictToDelete setValue:keyChainItemID forKey:(id)kSecAttrGeneric];
    
    OSStatus deleteErr = noErr;
    deleteErr = SecItemDelete((CFDictionaryRef)dictToDelete);
    if (deleteErr != errSecSuccess) {
        NSLog(@"delete UUID from KeyChain Error!!! Error code:%ld", deleteErr);
        [dictToDelete release];
        return NO;
    }
    else {
        NSLog(@"delete success!!!");
    }
    
    [dictToDelete release];
    return YES;
}

BOOL updateUDIDInKeyChain(NSString* newUDID)
{
    
    NSMutableDictionary *dictForQuery = [[NSMutableDictionary alloc] init];
    
    [dictForQuery setValue:(id)kSecClassGenericPassword forKey:(id)kSecClass];
    
    NSData *keychainItemID = [NSData dataWithBytes:kKeychainUDIDItemIdentifier
                                            length:strlen(kKeychainUDIDItemIdentifier)];
    [dictForQuery setValue:keychainItemID forKey:(id)kSecAttrGeneric];
    [dictForQuery setValue:(id)kCFBooleanTrue forKey:(id)kSecMatchCaseInsensitive];
    [dictForQuery setValue:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
    [dictForQuery setValue:(id)kCFBooleanTrue forKey:(id)kSecReturnAttributes];
    
    NSDictionary *queryResult = nil;
    SecItemCopyMatching((CFDictionaryRef)dictForQuery, (CFTypeRef*)&queryResult);
    if (queryResult) {
        
        NSMutableDictionary *dictForUpdate = [[NSMutableDictionary alloc] init];
        [dictForUpdate setValue:[NSString stringWithUTF8String:kKeychainUDIDItemIdentifier] forKey:kSecAttrDescription];
        [dictForUpdate setValue:keychainItemID forKey:(id)kSecAttrGeneric];
        
        const char *udidStr = [newUDID UTF8String];
        NSData *keyChainItemValue = [NSData dataWithBytes:udidStr length:strlen(udidStr)];
        [dictForUpdate setValue:keyChainItemValue forKey:(id)kSecValueData];
        
        OSStatus updateErr = noErr;
        
        // First we need the attributes from the Keychain.
        NSMutableDictionary *updateItem = [NSMutableDictionary dictionaryWithDictionary:queryResult];
        [queryResult release];
        
        // Second we need to add the appropriate search key/values.
        // set kSecClass is Very important
        [updateItem setObject:(id)kSecClassGenericPassword forKey:(id)kSecClass];
        
        updateErr = SecItemUpdate((CFDictionaryRef)updateItem, (CFDictionaryRef)dictForUpdate);
        if (updateErr != errSecSuccess) {
            NSLog(@"Update KeyChain Item Error!!! Error Code:%ld", updateErr);
            
            [dictForQuery release];
            [dictForUpdate release];
            return NO;
        }
        else {
            NSLog(@"Update KeyChain Item Success!!!");
            [dictForQuery release];
            [dictForUpdate release];
            return YES;
        }
    }
    
    [dictForQuery release];
    return NO;
}


#endif


