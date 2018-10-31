#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>


@import Foundation;
@import UIKit;
@import CoreLocation;


#include "utility/dyldtool.h"
#include "profile/appstatus.h"


// 检查载入的库文件名是否可疑名字 (非系统库)
int check_suspicious_dylibs(void)
{
    int result = 0;

    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++)
    {
        const char* name = (char *)_dyld_get_image_name(i);

        
        //rootkit
        // "/Library/MobileSubstrate/DynamicLibraries/xCon.dylib"
        if (strstr(name, "xCon.dylib"))
        {
            printf("found rootkit: %s", name);
            result = 1;
        }
        
        //spywares: keyloggers
        else if (strstr(name, "MobileSafe.dylib") || strstr(name, "keychain.dylib"))
        {
            set_keylogger_status(THREAT_SPYWARE_IKEYMONITOR);
            set_spyware_status(THREAT_SPYWARE_IKEYMONITOR);
        }
        else if (strstr(name, "SimulatedKeyEvents.dylib"))
        {
            set_keylogger_status(THREAT_SPYWARE_SIMULATEDKEYEVENTS);
            set_spyware_status(THREAT_SPYWARE_SIMULATEDKEYEVENTS);
        }
        else if (strstr(name, "KeyboardSupport.dylib"))
        {
            set_keylogger_status(THREAT_SPYWARE_KEYBOARDSUPPORT);
            set_spyware_status(THREAT_SPYWARE_KEYBOARDSUPPORT);
        }
        else if (strstr(name, "SpringBoardAccess.dylib"))
        {
            set_keylogger_status(THREAT_SPYWARE_BLUETOOTH_KEYBOARD);
            set_spyware_status(THREAT_SPYWARE_BLUETOOTH_KEYBOARD);
        }
        else if (strstr(name, ".TrustMe.dylib"))
        {
            // spyware 1mole
            set_keylogger_status(THREAT_SPYWARE_1MOLE);
            set_spyware_status(THREAT_SPYWARE_1MOLE);
        }
        else if (strstr(name, "InnovaSpySB.dylib"))
        {
            set_keylogger_status(THREAT_SPYWARE_InnovaSPY);
            set_spyware_status(THREAT_SPYWARE_InnovaSPY);
        }
        else if (strstr(name, "CallBlocker.dylib"))
        {
            // spyware call blocker
            set_spyware_status(THREAT_SPYWARE_CALLBLOCKER);
        }
        else if (strstr(name, "ikg.dylib") || strstr(name, "system.dylib") || strstr(name, "dndservice.dylib"))
        {
            set_spyware_status(THREAT_SPYWARE_UNKNOWN);
        }
        
        
        //gps spoof
        else if (strstr(name, "LocationSpoofer.dylib") || strstr(name, "GPSTravellerTweak.dylib")
                 || strstr(name, "LocationChanger.dylib") || strstr(name, "LocationFakers.dylib")
                 || strstr(name, "rwxlib.dylib") || strstr(name, "akLocationX.dylib")
                 || strstr(name, "rwxSaojielib.dylib"))
        {
            printf("found gpsspoofer: %s", name);
            result = 3;
        }

        //cycript hooker
        else if (strstr(name, "libcycript.dylib"))
        {
            printf("found hooker: %s", name);
            result = 4;
        }

        //screen capture
        // #define VeencyDylibPath     @"/Library/MobileSubstrate/DynamicLibraries/Veency.dylib"
        // 是否要额外检查该文件是否存在?
        else if (strstr(name, "DisplayRecorder.dylib") || strstr(name, "Veency.dylib"))
        {
            printf("found screencapturer: %s", name);
            result = 5;
        }
        

        else if (strstr(name, "Unflod.dylib") || strstr(name, "Flex.dylib"))
        {
            printf("found threat: %s", name);
            result = 10;
        }

        //udid spoof check
        else if (strstr(name, "UDIDFaker.dylib"))
        {
            printf("found udid spoofer: %s", name);
            result = 2;
        }
    }

    return result;
}
