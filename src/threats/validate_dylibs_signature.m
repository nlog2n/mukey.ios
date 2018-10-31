#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>



#include "utility/dyldtool.h"
#include "threats/validate_encryption_info.h"
#include "threats/validate_codesign.h"


// return:  0 - OK,  others - threats
int validate_dylibs_signature(void)
{
    int status = 0;
    char cert[32] = {0};

    printf("check certificate for dyld image list: \n");

    // get count of all currently loaded DYLD
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0 ; i < count; ++i)
    {
        // print
        const char *dyld = _dyld_get_image_name(i); //Name of image (includes full path)
        printf("#%d, %s\n", i,  dyld);
        
        mach_header_t *header = (mach_header_t*) (unsigned long)_dyld_get_image_header(i);
        
        //  获取dyld image header中code signature segment大小及长度信息，
        //  然后读取相应的image file内容到缓存.
        if (read_image_certificate(header, cert) != 0)
        {
            status = 1;  // no signature
        }

        // 检查第index个载入的dyld image是否包含 fairplay encryption
        // return:  1 - encrypted, 0-no encryption, including LC_ENCRYPTION_INFO not found
        // if no code signer, mostly likely there would be no EncryptInfo section (e.g. simulator)
        if (read_image_encryption_info(header) != 1)
        {
            status = 1; // failed for DRM check
        }

    }


    printf( status == 0 ? "OK\n": "Fail\n");
    return status;
}
