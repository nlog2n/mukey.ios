#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dlfcn.h>


#include "profile/appstatus.h"


int check_sysfiles(void)
{
	int status = 0;
	struct stat stat_info;

	printf("check if malware/spyware files exist: ");

	if ( stat("/Library/MobileSubstrate/DynamicLibraries/xCon.dylib", &stat_info) == 0
	        || stat("/Library/MobileSubstrate/DynamicLibraries/xCon.plist", &stat_info) == 0 ) // success
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_XCON);
	}

	if ( stat("/Library/MobileSubstrate/DynamicLibraries/Veency.plist", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_VEENCY);
	}

	if ( stat("/usr/libexec/sftp-server", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_SFTP);
	}

	if ( stat("/usr/sbin/sshd", &stat_info) == 0 || stat("/usr/libexec/ssh-keysign", &stat_info) == 0
	        || stat("/usr/bin/sshd", &stat_info) == 0 || stat("/etc/ssh/sshd_config", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_SSHD);
	}

	if ( stat("/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_LIVECLOCK);
	}


	if ( stat("/System/Library/LaunchDaemons/com.ikey.bbot.plist", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_IKEY_BBOT);
	}


	if ( stat("/Applications/RockApp.app", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_ROCKAPP);
	}

	if ( stat("/Applications/Icy.app", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_ICY);
	}


	if ( stat("/Applications/WinterBoard.app", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_WINTERBOARD);
	}


    // SBSettings是一个越狱后安装的iOS系统增强插件.
	if ( stat("/private/var/mobile/Library/SBSettings/Themes", &stat_info) == 0
	        || stat("/Applications/SBSettings.app", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_SBSETTINGS);
	}


	if ( stat("/Applications/MxTube.app", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_MXTUBE);
	}


	if ( stat("/Applications/IntelliScreen.app", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_INTELLISCREEN);
	}


	if ( stat("/Applications/FakeCarrier.app", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_FAKECARRIER);
	}


	if ( stat("/Applications/blackra1n.app", &stat_info) == 0 )
	{
		status = 1;
        set_spyware_status(THREAT_SPYWARE_BLACKRAIN);
	}

    // Push library for jailbroken apps
    if ( stat("/Library/MobileSubstrate/DynamicLibraries/libpush.plist", &stat_info) == 0
        || stat("/Library/MobileSubstrate/DynamicLibraries/libpush.dylib", &stat_info) == 0 )
    {
        status = 1;
        set_spyware_status(THREAT_SPYWARE_LIBPUSH);
    }
    
    
    // ownSpy for iOS, 远程监听插件，越狱下安装。在Cydia中也隐藏，只能远程删除.
    if ( stat("/Library/MobileSubstrate/DynamicLibraries/OwnSpyTool", &stat_info) == 0
            || stat("/Library/OwnSpy.app/Info.plist", &stat_info) == 0
            || stat("/Library/OwnSpy.app/OwnSpyHideTool", &stat_info) == 0 )
    {
        status = 1;
        set_spyware_status(THREAT_SPYWARE_OWNSPY);
    }
    
    // 如果有任何一个可以文件存在，则说明是jailbreak后才安装上去的.
    if ( status != 0 )
    {
        set_root_jailbreak_status(THREAT_JAILBREAK_SUSPICIOUS_FILES);
    }

	printf( status == 0 ? "OK\n" : "Fail\n");
	return status;
}