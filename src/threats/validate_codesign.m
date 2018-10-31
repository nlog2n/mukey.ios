#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

#import <Foundation/Foundation.h>

#include "mulog.h"
#include "utility/dyldtool.h"
#include "crypto/mu_hash.h"
#include "threats/validate_mobileprovision.h"
#include "profile/appstatus.h"


//  func:  get certificate bytes for given loaded dyld image
//  input:   index  - dyld image index
//  output:  cert   -  32-byte buffer array
//  return:  0 - success,  others for failure
int read_image_certificate(mach_header_t *header, char *cert)
{
    // Step 1: 获取dyld image header中code signature segment大小及长度信息，
    //  然后读取相应的image file内容到缓存.
    size_t dataLen = 0;
    unsigned char* data = read_image_code_signature(header, &dataLen);
    if (!data)
    {
        return -1;  // failure querying code signature
    }
    
    // Step 2: 扫描data buffer中signer名字
    //certificate characteristic for Developer or Enterprise Distribution
    char *dev  = "iPhone Developer:";
    char *dist = "iPhone Distribution:";
    char *testflight = "TestFlight Beta Distribution";
    // search string by memory comparison
    void *signing_id = memmem(data, dataLen, dev, strlen(dev));
    if (signing_id == NULL)
        signing_id = memmem(data, dataLen, dist, strlen(dist));
    if (signing_id == NULL)
    {
        signing_id = memmem(data, dataLen, testflight, strlen(testflight));
        if (signing_id != NULL)  // for testflight beta testing
        {
            printf("warning: certificate is for testflight beta distribution.\n");
            // TODO: get certificate for testflight
            free(data);
            return 0; // OK and bypass
        }
        else
        {
            muLog("code signer id not found");
            free(data);
            return -4;
        }
    }

    
    NSString *signer = [NSString stringWithUTF8String:signing_id];
    printf("signer name in binary: %s\n", (char*)signing_id);
    
    // Step 3: 读provision 文件 (embedded.mobileprovision, Info.plist)
    //  比较 binary 中的 signer name 是否与 provision文件中的名字相同
    if (read_certificate_from_provision_file(signing_id, cert) == 0) // success
    {
        free(data);
        return 0;
    }
    free(data);
    return -5;
}



int check_my_code_signature()
{
    char cert[32] = {0};
    
    mach_header_t *header;
    header = get_my_image_header();
    if (!header)  // could not find image which contains main() symbol
    {
        printf("=>could not find app image.\n");
        set_binary_codesign_status(0);
        return -1;  // regarded as no certificate found
    }
    
    int status = read_image_certificate(header, cert);
    set_binary_codesign_status(status==0);
    
    return status;
}


