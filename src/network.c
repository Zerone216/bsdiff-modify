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
#include <sys/time.h>
#include <getopt.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "network.h"
#include "common.h"

struct ifreq ifr;
int SNDBUF = 204800;
int RCVBUF = 204800;
//计算ip头的校验和
unsigned short cksum(unsigned short *buf, int len)
{
	unsigned long sum = 0;

	for(sum = 0; len > 0; len--)
		sum += *buf++;

	sum = (sum & 0xFFFF) + (sum >> 16);
	sum += (sum >> 16);

	return ~sum;
}

void add_iphead(struct ip *iph, char *sip, char *dip, int size)
{
	iph->ip_v = IPVERSION;
	iph->ip_hl = sizeof(struct ip) >> 2;
	iph->ip_tos = 0;
	iph->ip_len = htons((u_short)sizeof(struct ip) + size);
	iph->ip_id = 0;
	iph->ip_off = 0;
	iph->ip_ttl = 255;
	iph->ip_p = IPPROTO_OUR;
	inet_pton(AF_INET, sip, &(iph->ip_src));
	inet_pton(AF_INET, dip, &(iph->ip_dst));
	iph->ip_sum = 0;
	iph->ip_sum = cksum((unsigned short *)iph, 16);
}

/*目的地址为广播.多播.单播*/
void add_dst_hw(u_int8_t *dest, u_int8_t *src, int trans_proto_choose)
{
	int mcast_addr[ETH_ALEN] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x58};
	int i;

	if(trans_proto_choose == 0)
		memset(dest, 0xff, ETH_ALEN);
	else if(trans_proto_choose == 1)
	{
		for(i = 0; i < ETH_ALEN; i++)
		{
			memcpy(&dest[i], (char *)&mcast_addr[i], 1);
		}

		Log(("my_mac_addr:%2.2x-%2.2x-%2.2x-%2.2x-%2.2x-%2.2x", SNIF_ADDR_MAC(dest)));
	}
	else
		memcpy(dest, src, ETH_ALEN);

}
/*源地址为0或者单播*/
void add_src_hw(u_int8_t *dest, u_int8_t *src)
{
	if(src == NULL)
		memset(dest, 0x00, ETH_ALEN);
	else
		memcpy(dest, src, ETH_ALEN);
}

int get_local_ip(struct in_addr	* addr)
{
	int sockfd;
	struct ifreq ifr;
	struct sockaddr_in sin;
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if(sockfd == -1)
	{
		Log(("socket error"));
		return -1;
	}

	strcpy(ifr.ifr_name, NETDEVICE_NAME); //Interface name

	if(ioctl(sockfd, SIOCGIFADDR, &ifr) == 0) //SIOCGIFADDR 获取interface address
	{
		memcpy(&sin, &ifr.ifr_addr, sizeof(ifr.ifr_addr));
		Log(("localip: %s\n", inet_ntoa(sin.sin_addr)));
		memcpy(addr, &sin.sin_addr, sizeof(struct in_addr));
	}

	return 0;
}

int get_local_ip_str(char * ipaddr)
{
	struct in_addr	 addr;
	int ret = get_local_ip(&addr);
	if(ret == 0)
	{
		strcpy(ipaddr,inet_ntoa(addr));
		return 0;
	}
	else
	{
		return -1;
	}
}

u_int8_t *get_mac_addr(void)
{
	u_int8_t *u;
	int sockfd;

	if((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
		Log(("create socket error"));

	strcpy(ifr.ifr_name, DEFAULT_DEVICE);

	if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0)
	{
		switch(ifr.ifr_hwaddr.sa_family)
		{
		case ARPHRD_ETHER:
			u = (u_int8_t *)&ifr.ifr_addr.sa_data;
			break;

		default:
			u = NULL;
		}
	}

	close(sockfd);
	return u;
}

/*添加公共MAC,IP,UDP头*/
void sadd_hw_ip_udp(char *head, int trans_proto_choose)
{
	int datalen;
	struct hw_ip_udp_pact *sb_head;

	sb_head = (struct hw_ip_udp_pact *)head;
	datalen = DATA_LEN;
	datalen += sizeof(struct udphdr);
	datalen += sizeof(struct package_t);
	/*添加IP头*/
	add_iphead(&sb_head->ip_header, SRC_IP, DST_IP, datalen);
	datalen += sizeof(struct ip);
	/*数据链路头*/
	sb_head->eth_header.ether_type = htons(ETHERTYPE_IP);

	if(trans_proto_choose == 1)
		add_dst_hw(sb_head->eth_header.ether_dhost, NULL, 1);
	else
		add_dst_hw(sb_head->eth_header.ether_dhost, NULL, 0);

	add_src_hw(sb_head->eth_header.ether_shost, get_mac_addr());
	return ;
}

void cadd_hw_ip_udp(char *head)
{
	int datalen;
	struct hw_ip_udp_pact *sb_head;

	sb_head = (struct hw_ip_udp_pact *)head;
	datalen = ERROR_LEN;
	datalen += sizeof(struct udphdr);
	datalen += sizeof(struct package_t);
	/*添加IP头*/
	add_iphead(&sb_head->ip_header, DST_IP, SRC_IP, datalen);
	datalen += sizeof(struct ip);
	/*数据链路头*/
	sb_head->eth_header.ether_type = htons(ETHERTYPE_IP);
	add_src_hw(sb_head->eth_header.ether_shost, get_mac_addr());

	unsigned char *u;
	u = sb_head->eth_header.ether_shost;
	Log(("HW Address: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n", u[0], u[1], u[2], u[3], u[4], u[5]));
	return ;
}

//初始化服务端组播socket
int init_multicast_server(char * group_ip, int group_port,struct sockaddr_in * srvaddr)
{
	int sockfd;
	/* 创建 socket 用于UDP通讯 */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0)
	{
		Log(("socket creating err in udptalk"));
		return -1;
	}
	
	unsigned int socklen;
	socklen = sizeof(struct sockaddr_in);
	memset(srvaddr, 0, socklen);
	srvaddr->sin_family = AF_INET;
	srvaddr->sin_port = htons(group_port);
	srvaddr->sin_addr.s_addr = inet_addr(group_ip);
	//inet_pton(AF_INET, g_localinfo.ipaddr, &srvaddr->sin_addr);
	
	/* 绑定端口和IP信息到socket上 */
	if(bind(sockfd, (struct sockaddr *) srvaddr, sizeof(struct sockaddr_in)) == -1)
	{
		Log(("Bind error\n"));
		return -1;
	}

	return sockfd;
}

//初始化单播socket
int init_uniqcast_socket(char * dst_addr, int port, struct sockaddr_in * srvaddr, struct sockaddr_in * localaddr)
{
	int sockfd;
	/* 创建 socket 用于UDP通讯 */
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sockfd < 0)
	{
		Log(("socket creating err in udptalk"));
		return -1;
	}

	int reuse = 1;
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0)
	{
		Log(("Setting SO_REUSEADDR error"));
		close(sockfd);
		return -1;
	}

	char localip[20];
	get_local_ip_str(localip);
	

	unsigned int socklen;
	socklen = sizeof(struct sockaddr_in);
	memset(srvaddr, 0, socklen);
	srvaddr->sin_family = AF_INET;
	srvaddr->sin_port = htons(port);
	srvaddr->sin_addr.s_addr = inet_addr(dst_addr);//inet_ntoa(localip));
	Log(("dst_addr=[%s],port=[%d]", dst_addr, port));
	
	memset(localaddr, 0, socklen);
	localaddr->sin_family = AF_INET;
	localaddr->sin_port = htons(port);
	localaddr->sin_addr.s_addr = inet_addr(localip);// htonl(INADDR_ANY);//
	Log(("localip=[%s],port=[%d]", localip, port));
	
	if(bind(sockfd, (struct sockaddr *)localaddr, sizeof(struct sockaddr_in)) == -1)/* 绑定端口和IP信息到socket上 */
	{
		Log(("Bind error\n"));
		return -1;
	}
	Log(("Bind ok"));
	
	return sockfd;
}

//初始化组播socket
int init_multicast_socket(char * group_ip, int group_port,struct sockaddr_in * local_addr)
{
	int sockfd;
	/* 创建 socket 用于UDP通讯 */
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(sockfd < 0)
	{
		Log(("socket creating err in udptalk"));
		return -1;
	}

	int reuse = 1;
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0)
	{
		Log(("Setting SO_REUSEADDR error"));
		close(sockfd);
		return -1;
	}

	char localip[20];
	get_local_ip_str(localip);
	Log(("group_ip=[%s],group_port=[%d],localip=[%s]", group_ip,group_port, localip));
	
	unsigned int socklen;
	socklen = sizeof(struct sockaddr_in);
	memset(local_addr, 0, socklen);
	local_addr->sin_family = AF_INET;
	local_addr->sin_port = htons(group_port);
	local_addr->sin_addr.s_addr = htonl(INADDR_ANY); // inet_addr(group_ip); // 
	
	/* 绑定端口和IP信息到socket上 */
	if(bind(sockfd,(struct sockaddr *)local_addr, sizeof(struct sockaddr_in)) == -1)
	{
		Log(("Bind error: %s\n",strerror(errno)));
		close(sockfd);
		return -1;
	}
	
	int loop = 0;
	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) == -1)
	{
		Log(("setsockopt IP_MULTICAST_LOOP failed!"));
		close(sockfd);
		return -1;
	}
	
	// 设置要加入组播的地址
	struct ip_mreq mreq;
	bzero(&mreq, sizeof(struct ip_mreq));
	mreq.imr_multiaddr.s_addr = inet_addr(group_ip);// 设置组地址
	mreq.imr_interface.s_addr = inet_addr(localip); //设置接收组播消息的主机的地址信息
	if(setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(struct ip_mreq)) == -1) //把本机加入组播地址，即本机网卡作为组播成员，只有加入组才能收到组播消息
	{
		Log(("setsockopt failed!"));
		close(sockfd);
		return -1;
	}

	
	return sockfd;
}

//初始化服务端组播socket
int init_multicast_client(char * localip,char * group_ip, int group_port,struct sockaddr_in * clnaddr)
{
	int sockfd;
	/* 创建 socket 用于UDP通讯 */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0)
	{
		Log(("socket creating err in udptalk"));
		return -1;
	}

	/*
	unsigned char ttl=255;  
	if(setsockopt(s,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl)) == -1)
	{
		Log(("setsockopt IP_MULTICAST_TTL failed!"));
		return -1;
	}
	struct in_addr addr;  
	addr = inet_addr(g_localinfo.ipaddr);
	if(setsockopt(sockfd,IPPROTO_IP,IP_MULTICAST_IF,&addr,sizeof(addr)) == -1)  
	{
		Log(("setsockopt IP_MULTICAST_IF failed!"));
		return -1;
	}
	*/
	
	int loop = 0;  
	if(setsockopt(sockfd,IPPROTO_IP,IP_MULTICAST_LOOP,&loop,sizeof(loop)) == -1)
	{
		Log(("setsockopt IP_MULTICAST_LOOP failed!"));
		return -1;
	}
	
	
	/* 设置要加入组播的地址 */
	struct ip_mreq mreq;
	bzero(&mreq, sizeof(struct ip_mreq));
	Log(("group_ip=[%s],localip=[%s]",group_ip,localip));
	mreq.imr_multiaddr.s_addr = inet_addr(group_ip);/* 设置组地址 */
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);;//inet_addr(localip);/* 设置接收组播消息的主机的地址信息 */
	if(setsockopt(sockfd, IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq, sizeof(struct ip_mreq)) == -1)/* 把本机加入组播地址，即本机网卡作为组播成员，只有加入组才能收到组播消息 */
	{
		Log(("setsockopt failed!"));
		return -1;
	}
	
	unsigned int socklen;
	socklen = sizeof(struct sockaddr_in);
	memset(clnaddr, 0, socklen);
	clnaddr->sin_family = AF_INET;
	clnaddr->sin_port = htons(group_port);
	clnaddr->sin_addr.s_addr = inet_addr(localip);
	if(bind(sockfd, (struct sockaddr *) clnaddr, sizeof(struct sockaddr_in)) == -1)/* 绑定端口和IP信息到socket上 */
	{
		Log(("Bind error\n"));
		return -1;
	}
	
	return sockfd;
}

int sendpkt(int fd, BYTE *mac, char *pkt_addr, int len, int type)
{

	int datalen;
	char send_buf[1500];
	struct sockaddr sa;
	struct hw_ip_udp_pact *head;

	bzero(send_buf, sizeof(send_buf));
	head = (struct hw_ip_udp_pact *)send_buf;

	/*MAC 地址*/
	if(mac == NULL)
		add_dst_hw(head->eth_header.ether_dhost, NULL, 0);
	else
		add_dst_hw(head->eth_header.ether_dhost, mac, 2);

	add_src_hw(head->eth_header.ether_shost, get_mac_addr());
	head->eth_header.ether_type = htons(ETHERTYPE_IP);

	if(len > TOTAL_DATA_LEN)
		Log(("the data size is too long"));

	datalen = len;
	datalen += sizeof(struct udphdr);
	datalen += sizeof(struct package_t);
	/*添加IP头*/
	add_iphead(&head->ip_header, SRC_IP, DST_IP, datalen);
	datalen += sizeof(struct ip);
	/*设置packet结构*/
	head->package.type = type;
	head->package.pack_size = len;	/*有效数据长度,不包括任何包头*/

	/*添加数据*/
	if(pkt_addr != NULL)
		memcpy(send_buf + sizeof(struct hw_ip_udp_pact), pkt_addr, len);

	strcpy(sa.sa_data, DEFAULT_DEVICE);	/*外出接口*/

	if(sendto(fd, send_buf, sizeof(send_buf), 0, &sa, sizeof(sa)) == -1)
	{
		Log(("sendto error[%d], type = %d errno = %d\n", fd, type, errno));
		return -1;
	}

	return 0;
}

int initsocket()
{
	int sockfd;
	struct ifreq req;   //he add 20161121

	if((sockfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) == -1)
		Log(("create socket error"));

	int flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK); //设置文件状态标志  为非阻塞模式

	if(setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &SNDBUF, sizeof(SNDBUF)) == -1) //用于任意类型、任意状态套接口的设置选项值
		Log(("setsockopt error\n"));

	//-----------------he add--------------------
	//解决组播不能断电续传的问题
	memset(&req, 0, sizeof(struct ifreq));
	memcpy(req.ifr_name, "eth0", 4);
	req.ifr_hwaddr.sa_data[0] = 0x01;
	req.ifr_hwaddr.sa_data[1] = 0x00;
	req.ifr_hwaddr.sa_data[2] = 0x5e;
	req.ifr_hwaddr.sa_data[3] = 0x00;
	req.ifr_hwaddr.sa_data[4] = 0x00;
	req.ifr_hwaddr.sa_data[5] = 0x58;

	if(ioctl(sockfd, SIOCADDMULTI, &req) < 0)
	{
		Log(("%s\n", strerror(errno)));
	}

	//-----------------end--------------------------------

	return sockfd;
}

//一直读套接字,直到读不到包为止
int recvpkt(int fd, BYTE *buff, int len, int ifAsy, BYTE *mac, int *type)
{
	fd_set r_set;
	int  rec_len;
	char recv_buf[1500];
	struct timeval time, *tm_p;
	struct hw_ip_udp_pact *head;
	int ret = 0;
	
	head = (struct hw_ip_udp_pact *)recv_buf;

	tm_p = &time;

	if(ifAsy == 1)
	{
		time.tv_sec = 0;
		time.tv_usec = 0;
	}
	else
		tm_p = NULL;

	while(1)
	{
		bzero(recv_buf, 1500);
		FD_ZERO(&r_set);
		FD_SET(fd, &r_set);

		if(select(fd + 1, &r_set, NULL, NULL, tm_p) == -1)
		{
			Log(("select error"));
			return 0;
		}

		if(FD_ISSET(fd, &r_set))
		{
			rec_len = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, NULL, NULL);

			if(rec_len == -1)
			{
				Log(("recvfrom error"));
				return 0;
			}

			if(head->ip_header.ip_p == IPPROTO_OUR)
			{
				if(head->package.pack_size > 1500 || head->package.pack_size < 0)  //20170928 mod by zhangsh 包头里记录的有效数据长度如果超出接收缓冲区的范围则直接返回0
					return 0;

				*type = head->package.type;
				memcpy(mac, head->eth_header.ether_shost, ETH_ALEN);
				memcpy(buff, recv_buf + sizeof(struct hw_ip_udp_pact), head->package.pack_size);
				ret = (head->package.pack_size);
				break;
			}
		}
		else  //没有包可以读了
			break;
	}

	return ret;
}

