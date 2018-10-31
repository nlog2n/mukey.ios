#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/errno.h>


// TARGET_IPHONE_SIMULATOR comes from TargetConditionals.h.
// You need to #include that file to make an effect.
#include <TargetConditionals.h>

#if TARGET_IPHONE_SIMULATOR
// for simulator ios 8.1, 9.3
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>

#else
// for device ios 9
// search modifications by "fanghui"
#include "netinet_local/socketvar.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include "netinet_local/tcp_var.h"
#endif


#define kNetInetTcpPcblist_cstr                     		"net.inet.tcp.pcblist"


// Able to list TCP/UDP connections on non-jailbroken iOS devices
// 也是利用了sysctl函数: sysctlbyname("net.inet.tcp.pcblist", ...)
// 可参考 netstat 源代码
// http://opensource.apple.com/source/network_cmds/network_cmds-396.6/netstat.tproj/
//
// 用到的数据结构:
//     struct xinpgen, defined in in_pcb.h,
//     struct xtcpcb,  defined in tcp_var.h,
//     struct tcpcb,   defined in tcp_var.h
//     struct inpcb,   defined in in_pcb.h
//     struct xsocket. defined in socketvar.h.


static int parse_struct_xinpgen(const char* buffer) //struct xinpgen *xig)
{
    int status = 0;
    
    struct xinpgen *xig;
    xig = (struct xinpgen *)buffer;
    
    //struct tcpcb *tp;
    struct inpcb *inp;
    struct xsocket *so;
    
    // search based on listening ports in network connection listing
    for (xig = (struct xinpgen *)((char *)xig + xig->xig_len);
         xig->xig_len > sizeof(struct xinpgen);
         xig = (struct xinpgen *)((char *)xig + xig->xig_len))
    {
        // tp = &((struct xtcpcb *)xig)->xt_tp;    // tp is not read here
        inp = &((struct xtcpcb *)xig)->xt_inp;
        so  = &((struct xtcpcb *)xig)->xt_socket;
        
        // swap port endianness
        unsigned short lport = ((inp->inp_lport >> 8) & 0xff) | ((inp->inp_lport & 0xff) << 8);
        unsigned short fport = ((inp->inp_fport >> 8) & 0xff) | ((inp->inp_fport & 0xff) << 8);
        
        printf("Local %d.%d.%d.%d:%d, Remote %d.%d.%d.%d:%d, UID %d, State %d, Sock %p\n",
               (inp->inp_laddr.s_addr      ) & 0xff,
               (inp->inp_laddr.s_addr >>  8) & 0xff,
               (inp->inp_laddr.s_addr >> 16) & 0xff,
               (inp->inp_laddr.s_addr >> 24) & 0xff,
               lport,
               (inp->inp_faddr.s_addr      ) & 0xff,
               (inp->inp_faddr.s_addr >>  8) & 0xff,
               (inp->inp_faddr.s_addr >> 16) & 0xff,
               (inp->inp_faddr.s_addr >> 24) & 0xff,
               fport,
               so->so_uid, so->so_state, (void*)so->xso_so);
        
        // ignore local connections: 127.0.0.1
        if ((inp->inp_laddr.s_addr == ((1 << 24) + 127)) && (inp->inp_faddr.s_addr == ((1 << 24) + 127)))
            continue;
        
        // port 62078 is for "iphone-sync" with iTunes
        // TCP Port 62078 is that it is referred to as iphone-sync and is used with the iTunes sync and is some how secured.
        // UDP 5353 comes up in my nmap scan as open/filtered - also what UPD Port 5353 is used for on iPad is limited to the local network for mDNS.
        // further reading: http://apple.stackexchange.com/questions/139447/how-to-interface-with-ios-lockdownd
        
        if (   (inp->inp_laddr.s_addr == 0) //INADDR_ANY)
            && (inp->inp_faddr.s_addr == 0) //INADDR_ANY)
            && (lport != 62078))
        {
            if (lport == 22)
            {
                // Port 22 is commonly used by SSH server, and also has to be opened by root user
                printf("found port 22 -sshd\n");
                status = 1;
            }
            else if (lport == 5900)
            {
                // Port 5900 is commonly used by VNC server
                printf("found port 5900 -vnc server\n");
                status = 1;
            }
            else if ((so->so_uid == 0) && (lport != 0))
            {
                // the port is owned by a root process, assumed as backdoor
                printf("port %d owned by root\n", lport);
                status = 1;
            }
            else
            {
                //printf("OK\n");
            }
            
            //TODO: 能否通过socket/port查到进程号或进程名字，类似 lsof命令。
        }
    }
    
    return status;
}





// data struct copied from freebsd <sys/file.h> for kernel
// #include <sys/file.h>
// #include <sys/types.h>
/*
 * Userland version of struct file, for sysctl
 */
struct xfile {
    size_t	xf_size;	/* size of struct xfile */
    pid_t	xf_pid;		/* owning process */
    uid_t	xf_uid;		/* effective uid of owning process */
    int	xf_fd;		/* descriptor number */
    void	*xf_file;	/* address of struct file */
    short	xf_type;	/* descriptor type */
    int	xf_count;	/* reference count */
    int	xf_msgcount;	/* references from message queue */
    off_t	xf_offset;	/* file offset */
    void	*xf_data;	/* file descriptor specific data */
    void	*xf_vnode;	/* vnode pointer */
    u_int	xf_flag;	/* flags (see fcntl.h) */
};

// port to proc
// also refer to: sockstat.c http://web.mit.edu/freebsd/head/usr.bin/sockstat/sockstat.c
// and lsof implementation: https://github.com/practicalswift/osx/tree/master/src/lsof
int get_process_for_socket()
{
    struct xfile *files;
    size_t fsize = 0;
    
    // this call won't work on non-jailbroken iphone 9
    if (sysctlbyname("kern.file", NULL, &fsize, NULL, 0) != 0)
    {
        printf("error: kern.file get size %s\n", strerror(errno));
        return -1; // error
    }
    files = malloc(fsize);
    if (files == NULL)
    {
        printf("error: malloc\n");
        return -1; // error
    }
    if (sysctlbyname("kern.file", files, &fsize, NULL, 0) != 0)
    {
        printf("error: kern.file get data\n");
        free(files);
        return -1; // error
    }
    
    fsize /= sizeof(struct xfile);  // get count
    
    printf("PID\tUID\tSocketPtr\n");  // pid and effective uid
    for (int i = 0; i < (int)fsize; i++)
    {
        printf("%u\t%u\t%p\n", files[i].xf_pid, files[i].xf_uid, files[i].xf_data);
        
        if ( files[i].xf_data != NULL )
        {
            // it actually point to struct socket in (struct xsocket*)->xso_so
            //   xf_data == (void*) xso_so ?
            
        }
    }
    
    return 0;
}


int check_tcp_ports(void)
{
	int status = 0;
    
    printf("check tcp ports: \n");
#if TARGET_IPHONE_SIMULATOR
    printf("Running in Simulator\n");
#else
    printf("Running on the Device\n");
#endif
    
    get_process_for_socket();
    
    // Step 1: use kernel sysctl to get buffer allocated for sockets
    
	// 1.a: init for kernel sysctl for tcp ports
	size_t len = 0;
	int res = sysctlbyname(kNetInetTcpPcblist_cstr, 0, &len, 0, 0);
	if (res < 0)
	{
		//  If sysctlbyname function call fails, fail gracefully
		printf("sysctl error: %d", res);
		return 0;
	}

    // 1.b: real call for kernel sysctl
	char *buf = (char*)malloc(sizeof(char) * len);
    if (!buf)
    {
        printf("malloc error\n");
        return 0;
    }
	res = sysctlbyname(kNetInetTcpPcblist_cstr, buf, &len, 0, 0);
	if (res < 0)
	{
		free(buf);
		printf("sysctl error: %d", res);
		return 0;
	}
    
    // Step 2: parse the buffer, which is in type of struct xinpgen
    status = parse_struct_xinpgen(buf);
    
	free(buf);
    return status;
}



#ifdef __TEST_MAIN_TCP_PORTS__

int main()
{
    check_tcp_ports();
    
    return 0;
}

#endif
