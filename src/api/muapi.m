#include <stdio.h>

#import "threats/validate_ios_jailbreak.h"
#import "threats/check_sysfiles.h"
#import "threats/validate_objc_methods.h"
#import "threats/validate_objc_funcptr.h"
#import "threats/check_ios_debugger.h"
#import "threats/validate_codesign.h"
#import "threats/validate_mobileprovision.h"
#import "threats/validate_encryption_info.h"
#import "threats/validate_dylibs_signature.h"
#import "threats/check_process_info.h"
#import "threats/check_tcp_ports.h"
#import "threats/check_ios_simulator.h"
#import "threats/anti_ptrace.h"
#import "threats/validate_appstore_receipt.h"
#import "threats/check_dylibs_suspicious.h"
#import "threats/block_screencapture.h"
#import "threats/block_screenrecord.h"
#import "threats/fishhook_check.h"
#import "threats/insert_dylib_check.h"
#import "threats/validate_inline_hook.h"
#import "threats/validate_func_ptr.h"

#include "api/muapi.h"





int overall_check(void)
{
    struct mukey_sepolicy   sepolicy;
    
    init_sepolicy(&sepolicy);
    
    init_app_status();
    
    printf("started...\n");
    
    if (sepolicy.enable_jailbreak_check)
    {
        check_jailbreak();   // OK
        check_sysfiles();  // OK
    }
    
    if (sepolicy.enable_simulator_check)
    {
        check_simulator();   // OK
    }
    
    if (sepolicy.enable_debugger_check)
    {
        check_debugger();    // OK
    }
    
    if (sepolicy.enable_ptrace_deny_attach)
    {
        deny_ptrace_attach();  // OK. this will block xcode debugserver to attach
    }
    
    
    if (sepolicy.enable_appstore_receipt_check)
    {
        validate_appstore_receipt();   // OK
    }
    
    if (sepolicy.enalbe_image_encryptioninfo_check)
    {
        check_my_encryption_info();  // OK
    }
    
    if (sepolicy.enalbe_image_codesignature_check)
    {
        check_my_code_signature();   // OK
        validate_mobileprovision();  // OK
    }
    
    if (sepolicy.enable_dylibs_tampering_check)
    {
        validate_dylibs_signature();  // check encryptioninfo&signature for all loaded libraries
    }
    
    
    if ( sepolicy.enable_fishhook_check)
    {
        fish_hook_check();  // OK
    }
    
    if ( sepolicy.enable_inlinehook_check)
    {
        validate_inline_hook(); // OK
    }
    
    if (sepolicy.enable_insert_dylib_check)
    {
        insert_dylib_check();  // OK
    }
    
    if (sepolicy.enable_func_source_check)
    {
        validate_function_pointers();  // OK
    }
    
    if (sepolicy.enable_suspicious_dylib_check)
    {
        check_system_dylibs();
        check_system_dylibs_2();
        check_suspicious_dylibs();
    }
    
    if (sepolicy.enable_objcfunc_tampering_check)
    {
        validate_all_objc_classes();
    }
    
    if (sepolicy.enable_backdoor_process_check)
    {
        check_kproc_pids();   // OK
    }
    
    if (sepolicy.enable_backdoor_port_check)
    {
        check_tcp_ports();  // OK
    }
    
    if (sepolicy.enable_screenshot_check)
    {
        check_screenshot();
    }
    
    if (sepolicy.enable_screenrecord_check)
    {
        is_screen_mirrored();
    }
    
    return 0;
}