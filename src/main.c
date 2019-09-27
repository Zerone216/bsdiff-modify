#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <linux/kernel.h>
#include <time.h>
#include <pthread.h>
#include "common.h"
#include "compress.h"
#include "bsdiffpatch.h"
#include "network.h"

#define GROUP_PORT  39619    
#define GROUP_IP_ADDR "224.0.1.9" 

char netdevname[32];

int main_b(int argv,char ** argc)
{
	char * oldfile = argc[1];
	char * newfile = argc[2];
	
	int oldfilesize = get_file_size(oldfile);
	BYTE * oldbuff = (BYTE *)malloc(oldfilesize);
	FileToMem(oldfile, oldbuff,oldfilesize);
	Log(("oldfilesize = [%d]",oldfilesize));
	
	int validsize = bz2_compressbuff(oldbuff,oldfilesize);
	Log(("validsize = [%d]",validsize));
	MemToFile(oldbuff,validsize,newfile);
	
	free_null(oldbuff);
	
	return 0;
}

int main(int argv,char ** argc)
{
	if(argv < 7)
	{
		Log(("Miss Parameters."));
		Log(("Useage: ./main delta -t [lzo/zstd/bz2] oldfile newfile deltafile"));
		Log(("Useage: ./main patch -t [lzo/zstd/bz2] oldfile patchfile newfile"));
		
		return 0;
	}
	
	char * oldfile = NULL;
	char * newfile = NULL;
	char * deltafile = NULL;
	
	if(strcmp(argc[1],"delta") == 0)
	{
		oldfile = argc[4];
		newfile = argc[5];
		deltafile = argc[6];
		
		BYTE ztype = 0;
		if(strcasecmp(argc[3],"bz2") == 0)
			ztype = BZ2;
		if(strcasecmp(argc[3],"lzo") == 0)
			ztype = LZO1X;
		if(strcasecmp(argc[3],"zstd") == 0)
			ztype = ZSTD;

		off_t oldfilesize = get_file_size(oldfile);
		BYTE * oldbuff = (BYTE *)malloc(oldfilesize);
		FileToMem(oldfile, oldbuff,oldfilesize);
		Log(("oldfilesize = [%d]",oldfilesize));
		
		off_t newfilesize = get_file_size(newfile);
		BYTE * newbuff = (BYTE *)malloc(newfilesize);
		FileToMem(newfile, newbuff,newfilesize);
		Log(("newfilesize = [%d]",newfilesize));
		
		off_t patchfilesize = oldfilesize+newfilesize;
		BYTE * patchbuff = (BYTE *)malloc(patchfilesize);
		memset(patchbuff,0,patchfilesize);
		
		off_t validsize = create_delta_memory(oldbuff,oldfilesize,newbuff,newfilesize,patchbuff,patchfilesize,ztype);
		Log(("delta size = [%d]",validsize));
		
		MemToFile(patchbuff,validsize,deltafile);
		
		free_null(oldbuff);
		free_null(newbuff);
		free_null(patchbuff);
	}
	else if(strcmp(argc[1],"patch") == 0)
	{
		oldfile = argc[4];
		deltafile = argc[5];
		newfile = argc[6];

		BYTE ztype = 0;
		if(strcasecmp(argc[3],"bz2") == 0)
			ztype = BZ2;
		if(strcasecmp(argc[3],"lzo") == 0)
			ztype = LZO1X;
		if(strcasecmp(argc[3],"zstd") == 0)
			ztype = ZSTD;
		
		off_t patchfilesize = get_file_size(deltafile);
		BYTE * patchbuff = (BYTE *)malloc(patchfilesize);
		memset(patchbuff,0,patchfilesize);
		FileToMem(deltafile, patchbuff,patchfilesize);
		Log(("patchfilesize = [%d]",patchfilesize));
		
		off_t newfilesize = 0;
		memcpy(&newfilesize,patchbuff+24,8);
		BYTE * newbuff = (BYTE *)malloc(newfilesize);
		memset(newbuff,0,newfilesize);
		
		off_t oldfilesize = get_file_size(oldfile);
		Log(("oldfilesize = [%d]",oldfilesize));
		BYTE * oldbuff = (BYTE *)malloc(oldfilesize);
		FileToMem(oldfile, oldbuff,oldfilesize);
		
		
		off_t validsize = 0;
		validsize = apply_patch_memory(oldbuff,oldfilesize,patchbuff,patchfilesize,newbuff,newfilesize,ztype);
		Log(("newfilesize = [%d]",validsize));
		
		MemToFile(newbuff,validsize,newfile);
		
		free_null(oldbuff);
		free_null(newbuff);
		free_null(patchbuff);
	}
	else
	{
		Log(("Error Parameter!"));
		return 0;
	}
	
	
	return 0;
}

int main_f(int argv,char ** argc)
{
	if(argv < 5)
	{
		Log(("Miss Parameters."));
		Log(("Useage: ./main delta oldfile newfile deltafile"));
		Log(("Useage: ./main patch oldfile patchfile newfile"));
		
		return 0;
	}
	
	char * oldfile = NULL;
	char * newfile = NULL;
	char * deltafile = NULL;
	
	if(strcmp(argc[1],"delta") == 0)
	{
		oldfile = argc[2];
		newfile = argc[3];
		deltafile = argc[4];
		create_delta_file(oldfile,newfile,deltafile);
	}
	else if(strcmp(argc[1],"patch") == 0)
	{
		oldfile = argc[2];
		newfile = argc[4];
		deltafile = argc[3];
		apply_patch_file(oldfile,deltafile,newfile);
	}
	else
	{
		Log(("Error Parameter!"));
		return 0;
	}
	
	
	
	return 0;
}

int break_flag = 0;
int datasize = 0;

void calc_trans_speed_thread()
{
	int tmp_size = 0;
	int speed = 0;
	int times = 0;
	while(break_flag == 0)
	{
		times ++;
		speed = (datasize - tmp_size)/(1024);
		Log(("[%d] datasize = [%d], speed = %d KB/s",times,datasize,speed));
		tmp_size = datasize;
		sleep(1);
	}

	pthread_exit(0);
}

#define BUF_SIZE 1500
int main_s(int argv,char ** argc)
{
	if(argv < 3)
	{
		Log(("Miss Parameters."));
		Log(("Useage: ./main -srv"));
		Log(("Useage: ./main -clt"));
		
		return 0;
	}
	
	memset(netdevname , 0, 32);
	int ret = get_cmd_output("cat /proc/net/dev | grep -v lo | grep -v Inter | grep -v face | awk '{print $1}' | awk -F ':' '{print $1}'", netdevname, 32); //获取网卡名称
	if(ret == -1)
	{
		Log(("get netcard devname Failed!"));
	}
	Log(("netdevname = [%s]", netdevname));
	
	pthread_t  show_speed;
	ret = pthread_create(&show_speed, NULL, (void *)calc_trans_speed_thread,NULL);
	if(ret != 0)
	{
		Log(("Create Websocket_thread failed!\n"));
		exit(1);
	}
	
	if(strcmp(argc[1],"-srv") == 0)
	{
		struct sockaddr_in srvaddr;
		struct sockaddr_in localaddr;
		//int sockfd = init_multicast_server(GROUP_IP_ADDR,8060,&srvaddr);
		int sockfd = init_uniqcast_socket(GROUP_IP_ADDR,GROUP_PORT,&srvaddr,&localaddr);
		char buf[BUF_SIZE];
		int len = 0;
		
		FILE * fp = fopen(argc[2],"rb");
		if(fp == NULL)
		{
			Log(("fopen %s failed!",argc[2]));
		}
		Log(("fopen %s succeed!",argc[2]));

		while(1)
		{
			memset(buf,0,BUF_SIZE);
			len = fread(buf,BUF_SIZE,1,fp);
			if(len <= 0)
				break;
			
			len = sendto(sockfd, buf, strlen(buf), 0,(struct sockaddr *)&srvaddr, sizeof(srvaddr));
			if(len < 0)
			{
				break;
			}
			datasize += len;
			
			usleep(10);
		}
		
		fclose(fp);
		close(sockfd);
	}
	if(strcmp(argc[1],"-clt") == 0)
	{
		struct sockaddr_in cltaddr;
		struct in_addr ipaddr;
		get_local_ip(&ipaddr);
		//int sockfd = init_multicast_client(inet_ntoa(ipaddr),"227.0.1.1",8060,&cltaddr);
		int sockfd = init_multicast_socket(GROUP_IP_ADDR,GROUP_PORT,&cltaddr);
		char buf[BUF_SIZE];
		int ret = 0;
		socklen_t len = sizeof(cltaddr);
		
		FILE * fp = fopen(argc[2],"wb");
		if(fp == NULL)
		{
			Log(("fopen %s failed!",argc[2]));
		}
		Log(("fopen %s succeed!",argc[2]));
		
		while(1)
		{
			memset(buf,0,BUF_SIZE);
			ret = recvfrom(sockfd, buf, BUF_SIZE, 0, (struct sockaddr *)&cltaddr, &len);
			if(ret < 0)
			{
				break;
			}
			
			//ret = fwrite(buf,BUF_SIZE,1,fp);
			//if(ret <= 0)
			//	break;
			
			datasize += ret;
		}
		fclose(fp);
		close(sockfd);
	}
	
	break_flag = 1;
	
	pthread_join(show_speed, NULL); 
	
	return 0;
}
	
