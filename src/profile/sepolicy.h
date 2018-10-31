#ifndef __MUKEY_SEPOLICY_H__
#define __MUKEY_SEPOLICY_H__

#include <stdlib.h>

struct mukey_sepolicy {
    uint32_t  enable_jailbreak_check;
    uint32_t  enable_simulator_check;
    
    uint32_t  enable_debugger_check;
    uint32_t  enable_ptrace_deny_attach;
    
    uint32_t  enable_appstore_receipt_check;      // iOS only
    
    uint32_t  enalbe_image_encryptioninfo_check;
    uint32_t  enalbe_image_codesignature_check;
    uint32_t  enable_dylibs_tampering_check;
    uint32_t  enable_suspicious_dylib_check;
    uint32_t  enable_objcfunc_tampering_check;
    
    uint32_t  enable_backdoor_process_check;
    uint32_t  enable_backdoor_port_check;
    
    uint32_t  enable_screenshot_check;
    uint32_t  enable_screenrecord_check;
    
    
    uint32_t  enable_fishhook_check;  // iOS only
    
    uint32_t  enable_inlinehook_check;
    
    uint32_t  enable_insert_dylib_check;   // iOS only
    
    uint32_t  enable_func_source_check;
};



#ifdef __cplusplus
extern "C" {
#endif
    
    void init_sepolicy(struct mukey_sepolicy *sepolicy);
    
#ifdef __cplusplus
}
#endif

#endif