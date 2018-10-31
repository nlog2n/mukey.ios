
#import <stdio.h>
#import <dlfcn.h>

#include "utility/dyldtool.h"


#include "profile/appstatus.h"

// iPhone: Preventing Piracy:
//
// current process of cracking an application relies on stripping the
// application of encryption by attaching a debugger to the application
// on a jailbroken phone, dumping the text section containing the program
// code, and reinserting it into the original binary. The below code
// checks for the existence of LC_ENCRYPTION_INFO, and verifies that
// encryption is still enabled. There are, of course, a number of ways
// to defeat this check, but that's the nature of copy protection:

// refer to: http://landonf.org/2009/02/index.html


// 检查自身这个app binary是否包含 EncryptionInfo
// return:   1 - encrypted, 0-no encryption, including LC_ENCRYPTION_INFO not found
int check_my_encryption_info ()
{
    mach_header_t *header;
    
    header = get_my_image_header();
    if (!header)  // could not find image which contains main() symbol
    {
        printf("=>could not find app image.\n");
        set_binary_encryption_status(0);
        return 0;  // regarded as not encrypted
    }
    
    int status = read_image_encryption_info(header);
    set_binary_encryption_status(status);
    
    return status;
}



