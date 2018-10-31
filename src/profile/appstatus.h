#ifndef __MUKEY_APP_STATUS_H__
#define __MUKEY_APP_STATUS_H__

#include <stdlib.h>

#include <Foundation/Foundation.h>



#define THREAT_JAILBREAK_SUSPICIOUS_FILES          100
#define THREAT_JAILBREAK_SUSPICIOUS_FILE_FSTAB     200
#define THREAT_JAILBREAK_SUSPICIOUS_FILE_LINKED    300
#define THREAT_JAILBREAK_FORK_CHILD_PROCESS        400
#define THREAT_JAILBREAK_FUNCTION_HOOKED           500
#define THREAT_JAILBREAK_SUSPICIOUS_DYLIBS         600
#define THREAT_JAILBREAK_SYSTEM_COMMAND            700
#define THREAT_JAILBREAK_ENV_DYLD_INSERT_LIBS      800
#define THREAT_JAILBREAK_PAGE_EXECUTION            900


#define STATUS_SIMULATOR_UIDEVICE_MODEL      1
#define STATUS_SIMULATOR_UIDEVICE_NAME       2
#define STATUS_SIMULATOR_PROCESSINFO_EVN     4
#define STATUS_SIMULATOR_X86_IMAGE           8
#define STATUS_SIMULATOR_HW_CPUTYPE          16
#define STATUS_SIMULATOR_HOSTINFO            32
#define STATUS_SIMULATOR_APP_RECEIPT         64
#define THREAT_SIMULATOR_XCODE               128



#define THREAT_DEBUGGER_GDB      1
#define THREAT_DEBUGGER_LLDB     2
#define THREAT_DEBUGGER_XCODE    3



#define THREAT_SPYWARE_UNKNOWN               1
#define THREAT_SPYWARE_IKEYMONITOR           2
#define THREAT_SPYWARE_SIMULATEDKEYEVENTS    3
#define THREAT_SPYWARE_KEYBOARDSUPPORT       4
#define THREAT_SPYWARE_BLUETOOTH_KEYBOARD    5
#define THREAT_SPYWARE_1MOLE                 6
#define THREAT_SPYWARE_InnovaSPY             7
#define THREAT_SPYWARE_CALLBLOCKER           8


#define THREAT_KEYBOARD_HOOK_UIKeyboardImpl        101
#define THREAT_KEYBOARD_HOOK_NSNotificationCenter  102
#define THREAT_KEYBOARD_HOOK_UITextField           103
#define THREAT_KEYBOARD_HOOK_UIWebFormDelegate     104


#define THREAT_SPYWARE_XCON           10
#define THREAT_SPYWARE_VEENCY         11
#define THREAT_SPYWARE_SSHD           12
#define THREAT_SPYWARE_SFTP           13
#define THREAT_SPYWARE_LIVECLOCK      14
#define THREAT_SPYWARE_IKEY_BBOT      15
#define THREAT_SPYWARE_ROCKAPP        16
#define THREAT_SPYWARE_ICY            17
#define THREAT_SPYWARE_WINTERBOARD    18
#define THREAT_SPYWARE_SBSETTINGS     19
#define THREAT_SPYWARE_MXTUBE         20
#define THREAT_SPYWARE_INTELLISCREEN  21
#define THREAT_SPYWARE_FAKECARRIER    22
#define THREAT_SPYWARE_BLACKRAIN      23
#define THREAT_SPYWARE_OWNSPY         24
#define THREAT_SPYWARE_LIBPUSH        25




#ifdef __cplusplus
extern "C" {
#endif
    
    void init_app_status(void);
    
    void set_root_jailbreak_status(int val);
    uint32_t get_root_jailbreak_status();
    
    void set_simulator_status(int val);
    
    void set_debugger_status(int val);
    
    void set_appstore_receipt_status(void);
    
    void set_binary_encryption_status(int val);
    void set_binary_codesign_status(int val);
    
    void set_screenshot_status(int val);
    void set_screenrecord_status(int val);
    
    void set_fishhook_status(void);
    void set_inline_hook_status(void);
    void set_func_tampered_status(void);
    
    void set_insert_dylib_status(void);
    
    void set_keylogger_status(int val);
    
    void set_spyware_status(int val);
    
    NSString* print_app_status(void);
    
#ifdef __cplusplus
}
#endif

#endif