#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netdb.h>
#include <ifaddrs.h>


#if ! defined(IFT_ETHER)
#define IFT_ETHER 0x6 /* Ethernet CSMACD */
#endif


// 获取 WiFi MAC 地址, 6 bytes
// 以下两种方法仅适用于iOS 6.0 and below
// iOS 7.0 及以上总是返回 02:00:00:00:00:00.
// Wifi MAC 地址在同一设备，不同iOS版本(ios6 and ios 7)上返回结果不一样。代码仅供参考.

// refer http://stackoverflow.com/questions/677530/how-can-i-programmatically-get-the-mac-address-of-an-iphone


// return:  mac len=6 bytes; 0 for fail
int get_mac_addr(unsigned char *macAddress)
{
    int                 mib[6];  // management information base
    size_t              length;
    char                *buf = NULL;   // buffer for message

    struct if_msghdr    *ifm;   // interface message struct
    struct sockaddr_dl  *sdl;   // socket struct
    
    // init
    //unsigned char       macAddress[6]={0};
    memset(macAddress, 0, 6);
    
    // Setup the management Information Base (mib)
    mib[0] = CTL_NET;        // Request network subsystem
    mib[1] = AF_ROUTE;       // Routing table info
    mib[2] = 0;
    mib[3] = AF_LINK;        // Request link layer information
    mib[4] = NET_RT_IFLIST;  // Request all configured interfaces
    
    // With all configured interfaces requested, get handle index
    if ((mib[5] = if_nametoindex("en0")) == 0)
    {
        printf("Error: if_nametoindex error\n");
        return 0;
    }
    
    // Get the size of the data available (store in len)
    if (sysctl(mib, 6, NULL, &length, NULL, 0) < 0)
    {
        printf("Error: sysctl, get mib length\n");
        return 0;
    }
    
    // Alloc memory based on above call
    if ((buf = malloc(length)) == NULL)
    {
        printf("Error: Memory allocation error\n");
        return 0;
    }
    
    // Get system information, store in buffer
    if (sysctl(mib, 6, buf, &length, NULL, 0) < 0)
    {
        printf("Error: sysctl, get mib buffer\n");
        free(buf);
        return 0;
    }
    
    // now extract mac address from buffer
    
    // Map msgbuffer to interface message structure
    ifm = (struct if_msghdr *) buf;
    
    // Map to link-level socket structure
    sdl = (struct sockaddr_dl *) (ifm + 1);
    
    // Copy link layer address data in socket structure to an array
    memcpy(macAddress, sdl->sdl_data + sdl->sdl_nlen, 6);
    
    free(buf);
    return 6;
}


// We look for interface "en0" on iPhone
// 该方法在没有网络连接时(Wifi disabled)依然可以获取MAC地址
int get_mac_addr2(unsigned char *macAddress)
{
    struct ifaddrs *            addrs;
    const struct ifaddrs *      cursor;
    const struct sockaddr_dl *  sdl;
    
    int status = 0;
    
    memset(macAddress, 0, 6);
    
    if (getifaddrs(&addrs) != 0)
    {
        printf("error: getifaddrs failed\n");
        return 0;
    }
    
    cursor = addrs;
    while (cursor != NULL)
    {
            if ( (cursor->ifa_addr->sa_family == AF_LINK)
                && (((const struct sockaddr_dl *) cursor->ifa_addr)->sdl_type == IFT_ETHER)
                && (strcmp(cursor->ifa_name, "en0") == 0))
            {
                sdl = (const struct sockaddr_dl *) cursor->ifa_addr;
                if (sdl->sdl_alen == 6)
                {
                    memcpy(macAddress, sdl->sdl_data + sdl->sdl_nlen, 6);
                    status = 6; // OK
                    break; // should i break?
                }
                else
                {
                    printf("error: getifaddrs sockaddr_dl mac len is not 6.\n");
                }
            }
            cursor = cursor->ifa_next;
    }
    
    freeifaddrs(addrs);
    return status;
}

