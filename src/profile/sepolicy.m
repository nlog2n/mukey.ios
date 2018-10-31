

#include "sepolicy.h"

void init_sepolicy(struct mukey_sepolicy *sepolicy)
{
    sepolicy->enable_jailbreak_check = 1;
    sepolicy->enable_simulator_check = 1;
    
    sepolicy->enable_debugger_check = 1;
    sepolicy->enable_ptrace_deny_attach  = 0;

    sepolicy->enable_appstore_receipt_check  = 1;
    sepolicy->enalbe_image_encryptioninfo_check = 1;
    sepolicy->enalbe_image_codesignature_check = 1;
    
    sepolicy->enable_dylibs_tampering_check = 0;
    sepolicy->enable_suspicious_dylib_check = 0;
    sepolicy->enable_objcfunc_tampering_check = 0;
    
    sepolicy->enable_backdoor_process_check = 0;
    sepolicy->enable_backdoor_port_check = 1;

    sepolicy->enable_screenshot_check = 1;
    sepolicy->enable_screenrecord_check = 1;
    
    sepolicy->enable_fishhook_check = 1;
    sepolicy->enable_inlinehook_check = 0;   // 查询dyld cache比较费时
    
    sepolicy->enable_insert_dylib_check = 1;
    sepolicy->enable_func_source_check = 1;
}