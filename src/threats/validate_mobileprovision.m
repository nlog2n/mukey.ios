#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <TargetConditionals.h>

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>


#include "mulog.h"
#include "utility/dyldtool.h"
#include "crypto/mu_hash.h"

#include "profile/appstatus.h"


// Validate certificate and provisioning profile

//  embedded.mobileprovision 文件的格式
/*
其实是一个 DER 格式的 PKCS#7 文件。
如下命令可以显示 .mobileprovision 中内含的所有证书：

$ openssl pkcs7 -inform DER -in embedded.mobileprovision -print_certs

开发者证书：
Extension: Apple Developer Certificate (Development) ( 1.2.840.113635.100.6.1.2 )
Critical: YES
Data: 05 00

提交证书：
Extension: Apple Developer Certificate (Submission) ( 1.2.840.113635.100.6.1.4 )
Critical: YES
Data: 05 00

签过名的 IPA 文件其实是个 ZIP 包，解开以后里面有个 Payload 目录，Payload 目录里就是 xxx.app，
xxx.app里面有个 embedded.mobileprovision。
xxx.app 里面还有个 _CodeSignature 目录。_CodeSignature 里面有个叫 CodeResources 的文件，里面列出了此 App 的所有文件还有文件的签名。
*/



/** embedded.mobileprovision plist format:
 
 AppIDName, // string — TextDetective
 ApplicationIdentifierPrefix[],  // [ string - 66PK3K3KEV ]
 CreationData, // date — 2013-01-17T14:18:05Z
 DeveloperCertificates[], // [ data ]
 Entitlements {
 application-identifier // string - 66PK3K3KEV.com.blindsight.textdetective
 get-task-allow // true or false
 keychain-access-groups[] // [ string - 66PK3K3KEV.* ]
 },
 ExpirationDate, // date — 2014-01-17T14:18:05Z
 Name, // string — Barrierefreikommunizieren (name assigned to the provisioning profile used)
 ProvisionedDevices[], // [ string.... ]
 TeamIdentifier[], // [string — HHBT96X2EX ]
 TeamName, // string — The Blindsight Corporation
 TimeToLive, // integer - 365
 UUID, // string — 79F37E8E-CC8D-4819-8C13-A678479211CE
 Version, // integer — 1
 ProvisionsAllDevices // true or false  ***NB: not sure if this is where this is
 */



// parsing your iOS app's embedded.mobileprovision at runtime.
// parse provision file (for code sign)
// return:  NSDictionary or nil for failure
// 参考: https://github.com/blindsightcorp/BSMobileProvision
NSDictionary *get_mobileprovision()
{
    static NSDictionary* mobileProvision = nil;
    
    if (!mobileProvision)
    {
        NSString *provisioningPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
        if (!provisioningPath)
        {
            return nil;
        }
        
        // NSISOLatin1 keeps the binary wrapper from being parsed as unicode and dropped as invalid
        NSString *binaryString = [NSString stringWithContentsOfFile:provisioningPath encoding:NSISOLatin1StringEncoding error:NULL];
        if (!binaryString)
        {
            muLog("embedded.mobileprovision not found or empty");
            return nil;
        }
        
        NSScanner *scanner = [NSScanner scannerWithString:binaryString];
        BOOL ok = [scanner scanUpToString:@"<plist" intoString:nil];
        if (!ok)
        {
            muLog("unable to find beginning of plist");
            return nil;
        }
    
        NSString *plistString;
        ok = [scanner scanUpToString:@"</plist>" intoString:&plistString];
        if (!ok)
        {
            muLog("unable to find end of plist");
            return nil;
        }
        plistString = [NSString stringWithFormat:@"%@</plist>", plistString];

        // juggle latin1 back to utf-8!
        NSData *plistdata_latin1 = [plistString dataUsingEncoding:NSISOLatin1StringEncoding];
        NSError *error = nil;
        
        mobileProvision = [NSPropertyListSerialization propertyListWithData:plistdata_latin1
                                                                              options:NSPropertyListImmutable
                                                                               format:NULL
                                                                                error:&error];
        if (error)
        {
            muLog("error parsing extracted plist — %@",error);
            mobileProvision = nil;
            return nil;
        }
    }
    
    return mobileProvision;
}


// determine at runtime whether your app is being distributed as
// sim, dev, ad hoc, app store, enterprise. or -1 for unknown
int read_mobileprovision_release(void)
{
    NSDictionary *mobileProvision = get_mobileprovision();
    if (!mobileProvision)
    {
        return -1; // fail to read
        
        // notes that even when an app (such as one released through the app store) does not have an embedded.mobileprovision,
        // the application binary will still be signed.
        
    }
    else if (![mobileProvision count])
    {
#if TARGET_IPHONE_SIMULATOR
        return 1;  // Release for Sim;
#else
        return 0;  // Release for AppStore;
#endif
    }
    else if ([[mobileProvision objectForKey:@"ProvisionsAllDevices"] boolValue])
    {
        // enterprise distribution contains ProvisionsAllDevices - true
        return 2;  // Release for Enterprise;
    }
    else if (   [mobileProvision objectForKey:@"ProvisionedDevices"]
             && [[mobileProvision objectForKey:@"ProvisionedDevices"] count] > 0)
    {
        // development contains UDIDs and get-task-allow is true
        // ad hoc contains UDIDs and get-task-allow is false
        NSDictionary *entitlements = [mobileProvision objectForKey:@"Entitlements"];
        if ([[entitlements objectForKey:@"get-task-allow"] boolValue])
        {
            return 3; // Release for Dev;
        }
        else
        {
            return 4; // Release for AdHoc;
        }
    }
    else
    {
        // app store contains no UDIDs (if the file exists at all?)
        return 0;  // Release for AppStore;
    }
}


// read bundle identifier and validate
// output: bundle identfier
// return:  0 - OK
int read_mobileprovision_bundle_identifier(char* outBundleIdentifier)
{
    NSDictionary *mobileProvision = get_mobileprovision();
    if (!mobileProvision)
    {
        return -1; // fail to read
    }
   
    // refer to: .mobileprovision Files Structure and Reading
    //  https://web.archive.org/web/20130502092617/http://idevblog.info/mobileprovision-files-structure-and-reading
    // mobileprovisionParser.m
    //  https://github.com/mattjgalloway/mobileprovisionParser/blob/master/Source/mobileprovisionParser.m
    //
    NSDictionary *entitlements = [mobileProvision objectForKey:@"Entitlements"];
    NSString *app_id = [entitlements objectForKey:@"application-identifier"]; // with prefix
    muLog("app identifier in mobileprovision=%@", app_id);
    
    // 或者: 扫描 LC_CODE_SIGNATURE memory获取 application-identifier?
    //  这个应该是和.mobileprovision文件中导进来的.
    
    // 然后从info.plist文件中读取bundleIdentifier.
    // 这些NSBundle函数都是针对info.plist操作的，可以获取对应的键值：
    //  bundleIdentifier，返回NSString类型的bundle identifier
    //  infoDictionary，返回整个info.plist内容，返回类型NSDictionary
    //  objectForInfoDictionaryKey:，依据Key值返回对应的键值
    // 不过需要指出的是上述dictionary的key值并不是显示在plist中的字符串，这一点通过打印出infoDictionary的结果就可以看出。
    
    NSString *bundleIdentifier = [[NSBundle mainBundle] bundleIdentifier]; // without prefix
    muLog("bundle identifier from NSBundle=%@", bundleIdentifier);
    
    // 还应检查两个文件中bundle identifier是否一致?
    if ( [app_id rangeOfString:bundleIdentifier].location == NSNotFound )
    {
        muLog("bundle identifier mismatch: %@, %@", app_id, bundleIdentifier);
        return -2; // mismatch
    }
    
    // TODO: 保存bundle identifier以备以后比较.

    return 0;
}




// input:  provision file,  signer name
// output:  signer's certificate
// return:  0 OK, others failure
int read_certificate_from_provision_file(char* signing_id, char *cert)
{
    NSDictionary *mobileProvision = get_mobileprovision();
    if (!mobileProvision)
    {
        return -1; // fail
    }
    
    if ([mobileProvision objectForKey:@"DeveloperCertificates"] == nil)
    {
        return -1;
    }
    
    NSArray * developercerts = [mobileProvision objectForKey:@"DeveloperCertificates"];
    if (developercerts.count == 0)
    {
        return -1;
    }
    
    
    // 按给定的binary 中的 signer name 来查找provision文件中是否包含该名字的certificate
    NSString *signer = [NSString stringWithUTF8String:signing_id];
    
    for (int j = 0; j < developercerts.count; j++)
    {
        SecCertificateRef cert_ref = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)developercerts[j]);
        if( cert_ref != NULL )
        {
            // 从 provision 文件中找到名字 summaryString
            CFStringRef certSummary = SecCertificateCopySubjectSummary(cert_ref);
            NSString* summaryString = [[NSString alloc] initWithString:(__bridge NSString*)certSummary];
            
            if ([summaryString isEqualToString:signer])
            {
                // 如相同则将该certificate的hash保存下来
                printf("binary signer name matched: %s\n", signing_id);
                CFRelease(certSummary);
                
                NSData *certdata = mu_sha256_nsdata(developercerts[j]);
                memcpy(cert, certdata.bytes, 32);
                return 0;  // OK
            }
         
            CFRelease(certSummary);
        }
    }
    
    return -1;
}


// 读取info.plist，如果发现了SignerIdentity的键，就认为IPA被破解
// iPhone应用的发布是通过iTunes，用户下载之后会对程序产生一个对应你iTunes帐号的签名。
// 而破解，正是需要去掉这个签名，让它可以安装在 每一个帐号上。但是安装过程还是需要欺骗iTunes，告诉它这个程序是已经签名了的。
// 这个破解的签名在哪里呢？对了，就是每个应用或游戏下的Info.plist文件，
// 如果你下载过破解的 iPhone应用来研究。就会发现所有的破解程序都有这个一个键值key-value pair：
// {SignerIdentity, Apple iPhone OS Application Signing}
// 参考: http://thwart-ipa-cracks.blogspot.sg/2008/11/detection.html
//    该文还建议检查 info.plist文件子节数及是否binary/xml格式
int validate_info_plist(void)
{
    NSBundle *bundle = [NSBundle mainBundle];
    NSDictionary *info = [bundle infoDictionary];
    if ([info objectForKey: @"SignerIdentity"] != nil)
    {
        printf("wrong info.plist file: app pirated!\n");
        return 1;  // IPA cracked
    }
    
    return 0;
}


// API call
int validate_mobileprovision(void)
{
    char bundle_identifier[256] = {0}; // string
    
    read_mobileprovision_release(); // 目前对不同release没有进一步动作.
    
    read_mobileprovision_bundle_identifier(bundle_identifier);
    
    validate_info_plist();
    
    return 0;
}
