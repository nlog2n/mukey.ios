#ifndef __VALIDATE_CODESIGN_H__
#define __VALIDATE_CODESIGN_H__


#include "utility/dyldtool.h"


#ifdef __cplusplus
extern "C" {
#endif
    
    int check_my_code_signature();
    
    int read_image_certificate(mach_header_t *header, char *cert);
    
#ifdef __cplusplus
}
#endif


#endif
