#ifndef _NETWORK_H_
#define _NETWORK_H_


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <bits/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/sem.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "common.h"
extern char netdevname[32];
#define NETDEVICE_NAME netdevname
#define INVALID_SOCKET  (SOCKET)(~0)
#define SOCKET_ERROR            (-1)

#define NBUFF 2
#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define SYSEM_MODE 00666
#define SEM_MODE (IPC_CREAT | SYSEM_MODE)

#define IPPROTO_OUR 0x5A
#define DATA_LEN 1024
#define TOTAL_DATA_LEN 1430
#define PADDING 4
#define ERROR_LEN 1024

#define SNIF_ADDR_MAC(p)     \
    _XFF((p)[0]),_XFF((p)[1]),_XFF((p)[2]),_XFF((p)[3]),_XFF((p)[4]),_XFF((p)[5])
    
#define SRC_IP "0.0.0.0"
#define DST_IP "255.255.255.255"
#define DEFAULT_DEVICE "eth0"

#pragma pack(1)

struct package_t
{
	int type;		/*数据包类型*/
	int total_group;	/*总组数*/
	int total_packet;	/*当前组的总包数*/
	int pack_size;		/*包的有效数据*/
	int group_id;		/*当前组ID*/
	int seq_id;		/*当前包ID*/
	DWORD sender_breaknum;  /*断点续传标记*/
};

struct hw_ip_udp_pact
{
	struct ether_header eth_header;
	struct ip ip_header;
	struct udphdr udp_header;
	struct package_t package;
};


#pragma pack()
unsigned short cksum(unsigned short *buf, int len);
void add_iphead(struct ip *iph, char *sip, char *dip, int size);
u_int8_t *get_mac_addr(void);
int get_local_ip(struct in_addr	* addr);
int get_local_ip_str(char * ipaddr);
void sadd_hw_ip_udp(char *head, int trans_proto_choose);
void cadd_hw_ip_udp(char *head);
void add_iphead(struct ip *iph, char *sip, char *dip, int size);
void add_dst_hw(u_int8_t *dest, u_int8_t *src, int trans_proto_choose);
void add_src_hw(u_int8_t *dest, u_int8_t *src);
int init_uniqcast_socket(char * dst_addr, int port, struct sockaddr_in * srvaddr, struct sockaddr_in * localaddr);
int init_multicast_socket(char * group_ip, int group_port,struct sockaddr_in * cltaddr);
int init_multicast_server(char * group_ip, int group_port,struct sockaddr_in * srvaddr);
int init_multicast_client(char * localip,char * group_ip, int group_port,struct sockaddr_in * clnaddr);

int initsocket();
int sendpkt(int fd, BYTE *mac, char *pkt_addr, int len, int type);
int recvpkt(int fd, BYTE *buff, int len, int ifAsy, BYTE *mac, int *type);
#endif
