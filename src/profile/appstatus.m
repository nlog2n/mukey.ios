#include <stdio.h>
#include <stdlib.h>

#include "appstatus.h"

struct mukey_app_status {
    uint32_t jailbreak;             // is device jailbroken
    uint32_t simulator;             // is in simulator environment
    
    uint32_t debugger;              // is gdb or lldb debugger attached
    
    uint32_t appstore_receipt;      // is appstore receipt validated
    uint32_t binary_encryption;     // is my app NOT from appstore
    uint32_t binary_codesign;       // is my app binary signed by developer
    uint32_t dylibs_tampered;       // is any loaded dylib not encrypted or signed
    uint32_t objc_func_tampered;    // is obj-c method injected
    
    uint32_t backdoor_process;      // found any suspicous backdoor process names
    uint32_t backdoor_port;         // found any suspicous backdoor tcp ports
    
    
    uint32_t screenshot;            // is screenshot detected
    uint32_t screenrecord;          // is screen recorded, by airplay for example
    
    uint32_t fish_hooked;           // is function by fish hooked
    
    uint32_t insert_dylib;          // is LC_LOAD_DYLIB inserted
    
    uint32_t inline_hooked;         // is any loaded dylib runtime tampered against dyld cache
    
    uint32_t func_tampered;         // is function not from specified library
    
    uint32_t keylogged;             // is keyboard hooked
    uint32_t location_spoofed;      // is my GPS location spoofed
    
    uint32_t spyware;               // is there any spyware (sms,call etc)
    
};

struct mukey_app_status   app_status;


void init_app_status(void)
{
    // default values
    memset(&app_status, 0, sizeof(app_status));
}


void set_root_jailbreak_status(int val)
{
    app_status.jailbreak = val;
}

uint32_t get_root_jailbreak_status()
{
    return app_status.jailbreak;
}

void set_simulator_status(int val)
{
    app_status.simulator |= val;
}

void set_debugger_status(int val)
{
    app_status.debugger = val;
}

void set_appstore_receipt_status(void)
{
    app_status.appstore_receipt = 1;
}

void set_binary_encryption_status(int val)
{
    app_status.binary_encryption = val;
}

void set_binary_codesign_status(int val)
{
    app_status.binary_codesign = val;
}

void set_screenshot_status(int val)
{
    printf("screenshot detected.\n");
    app_status.screenshot = val;
}

void set_screenrecord_status(int val)
{
    app_status.screenrecord = val;
}

void set_fishhook_status(void)
{
    app_status.fish_hooked = 1;
}

void set_inline_hook_status(void)
{
    app_status.inline_hooked = 1;
}

void set_insert_dylib_status(void)
{
    app_status.insert_dylib = 1;
}

void set_func_tampered_status(void)
{
    app_status.func_tampered = 1;
}

void set_keylogger_status(int val)
{
    app_status.keylogged = val;
}


void set_spyware_status(int val)
{
    app_status.spyware = val;
}


NSString* print_app_status(void)
{
    /*
    printf("app status:\n");
    printf("root/jailbreak:     %X\n", app_status.jailbreak);
    printf("simulator/emulator: %X\n", app_status.simulator);
    printf("debugger attached:  %X\n", app_status.debugger);
    printf("appstore receipt:   %X\n", app_status.appstore_receipt);
    printf("binary encryption:  %X\n", app_status.binary_encryption);
    printf("binary codesign:    %X\n", app_status.binary_codesign);
    printf("library tampered:   %X\n", app_status.dylibs_tampered);
    printf("objc func tampered: %X\n", app_status.objc_func_tampered);
    printf("process backdoor:   %X\n", app_status.backdoor_process);
    printf("tcp port backdoor:  %X\n", app_status.backdoor_port);
    printf("screenshot:         %X\n", app_status.screenshot);
    printf("screenrecord:       %X\n", app_status.screenrecord);
    */
    
    NSString *jailbreak =        [NSString stringWithFormat:@"root/jailbreak:     %d\n", app_status.jailbreak];
    NSString *simulator =        [NSString stringWithFormat:@"simulator/emulator: %X\n", app_status.simulator];
    NSString *debugger =         [NSString stringWithFormat:@"debugger:           %d\n", app_status.debugger];
    NSString *appstore_receipt = [NSString stringWithFormat:@"appstore receipt:   %X\n", app_status.appstore_receipt];
    NSString *binary_encryption =[NSString stringWithFormat:@"binary encryption:  %X\n", app_status.binary_encryption];
    NSString *binary_codesign =  [NSString stringWithFormat:@"binary codesign:    %X\n", app_status.binary_codesign];
    NSString *library_tamper =   [NSString stringWithFormat:@"library tampered:   %X\n", app_status.dylibs_tampered];
    NSString *objc_func_tamper = [NSString stringWithFormat:@"objc func tampered: %X\n", app_status.objc_func_tampered];
    NSString *process_backdoor = [NSString stringWithFormat:@"process backdoor:   %X\n", app_status.backdoor_process];
    NSString *port_backdoor =    [NSString stringWithFormat:@"tcp port backdoor:  %X\n", app_status.backdoor_port];
    NSString *screenshot =       [NSString stringWithFormat:@"screenshot:         %X\n", app_status.screenshot];
    NSString *screenrecord =     [NSString stringWithFormat:@"screenrecord:       %X\n", app_status.screenrecord];
    NSString *fishhook     =     [NSString stringWithFormat:@"fish hook:          %X\n", app_status.fish_hooked];
    NSString *inlinehook     =   [NSString stringWithFormat:@"inline hook:        %X\n", app_status.inline_hooked];
    NSString *func_tampered  =   [NSString stringWithFormat:@"func tampered:      %X\n", app_status.func_tampered];
    NSString *insert_dylib =     [NSString stringWithFormat:@"insert dylib:       %X\n", app_status.insert_dylib];
    NSString *keylogged    =     [NSString stringWithFormat:@"keyboard logger:    %X\n", app_status.keylogged];
    NSString *spyware      =     [NSString stringWithFormat:@"spyware:            %d\n", app_status.spyware];
    
    NSString *retString = [NSString stringWithFormat:@"App Status:\n%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@%@",
                           jailbreak, simulator, debugger, objc_func_tamper,
                           binary_encryption, binary_codesign,
                           library_tamper, process_backdoor, port_backdoor,
                           appstore_receipt, screenshot, screenrecord,
                           fishhook, inlinehook, insert_dylib, func_tampered,
                           keylogged, spyware
                        ];

    return retString;
}