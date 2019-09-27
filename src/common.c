#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>		/* ANSI C header file */
#include <syslog.h>		/* for syslog() */
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/io.h>
#include <sys/stat.h>
//#include <time.h>
//#include <assert.h>

#include "common.h"

DDWORD get_file_size(char * filename)
{
	FILE *fp = NULL;
	struct stat statbuff;

	if(file_access(filename, F_OK))
	{
		Log(("The %s do not exist\n",filename));
		return 0;
	}
	if((fp = fopen(filename, "r")) == NULL)
	{
		Log(("Open file %s error ...\n",filename));
		return 0;
	}
	
	int fd = fileno(fp);
	fstat(fd, &statbuff);
	DDWORD filesize = statbuff.st_size;
	
	fclose(fp);
	return filesize;
}

int file_access(const char * filename, int mode)
{
	int ret;

	ret = access(filename, mode);

	if(ret == -1)
	{
		return 1;
	}

	return 0;
}

int free_null(void *p)
{
	if(p == NULL)
	{
		return 0;
	}
	else
	{
		//Log(("free point &=[0x%08x]",p));
		free(p);
		p = NULL;
		return 0;
	}
}

//把信息输出到屏幕，和日志文件中，当日志文件大小超过20M后，自动清空
void printmsg(const char *fmt, ...)
{
	va_list ap;
	FILE *fp;
	char buf[1024];
	struct stat statbuff;

	va_start(ap, fmt);

	vsprintf(buf, fmt, ap);					/* this is not safe */
	fputs(buf, stdout);

	fp = fopen(LOG_FILE_NAME, "a+");
	fstat(fileno(fp), &statbuff);

	if(statbuff.st_size > MAX_LOG_SIZE)
	{
		fclose(fp);
		//system("rm -rf /opt/nova/printmsg.log");
		system("rm -rf " LOG_FILE_NAME);

	}
	else
	{
		fputs(buf, fp);
		fclose(fp);
	}

	va_end(ap);

	return;
}

double Auto_trans_size(DDWORD x)
{
	if(x > (1024 * 1024 * 1024))
		return x * 1.0 / (1024 * 1024 * 1024);

	if(x > (1024 * 1024))
		return x * 1.0 / (1024 * 1024);

	if(x > 1024)
		return x * 1.0 / 1024;
	else
		return x;
}

void MoveToChar(char cas, char * string)
{
	int i = 0, j = 0;

	for(i = 0; i < strlen(string); i ++)
	{
		if(cas == string[i])
		{
			break;
		}
	}

	for(j = 0; j < strlen(string) - i - 1; j ++)
	{
		string[j] = string[j + i + 1];
	}

	memset(string + strlen(string) - i - 1, 0x00, i);
}

void RemoveChar(char * string, char cas)
{
	int i = 0, j = 0;
	char tmp[256] = {0};

	for(i = 0; i < strlen(string); i ++)
	{
		if(cas == string[i])
		{
			continue;
		}

		tmp[j ++] = string[i];
	}

	memset(string, 0x00, strlen(string));
	strcpy(string, tmp);
}


void StringSplite(char * string, char cfs, char strarr[][5])
{
	int i = 0, j = 0, k = 0;
	int flag[100] = {0};

	for(i = 0; i < strlen(string); i ++)
	{
		if(cfs == string[i])
		{
			flag[j++] = i;
		}
	}

	int start = 0, slen = flag[0] - 0;

	for(i = 0; i < j + 1; i ++)
	{
		memcpy(strarr[k ++], string + start, slen);
		strarr[k - 1][slen] = '\0';

		start = flag[i] + 1;

		if(i == j - 1)
			slen = strlen(string) - start;
		else
			slen = flag[i + 1] - start;
	}
}

void IpstrToArray(char * ipstr, BYTE * iparray)
{
	char ipblock[4][5];
	StringSplite(ipstr, '.', ipblock);
	int i = 0;

	for(i = 0; i < 4; i ++)
	{
		iparray[i * 2] = atoi(ipblock[i]);
	}
}
char * itoa(int num, char*str, int radix)
{
	/*索引表*/
	char index[] = "0123456789ABCDEF";
	unsigned unum;/*中间变量*/
	int i = 0, j, k;

	/*确定unum的值*/
	if(radix == 10 && num < 0) /*十进制负数*/
	{
		unum = (unsigned) - num;
		str[i++] = '-';
	}
	else
		unum = (unsigned)num; /*其他情况*/

	/*转换*/
	do
	{
		str[i++] = index[unum % (unsigned)radix];
		unum /= radix;
	}
	while(unum);

	str[i] = '\0';

	/*逆序*/
	if(str[0] == '-')
		k = 1; /*十进制负数*/
	else
		k = 0;

	char temp;

	for(j = k; j <= (i - 1) / 2; j++)
	{
		temp = str[j];
		str[j] = str[i - 1 + k - j];
		str[i - 1 + k - j] = temp;
	}

	return str;
}

int MemToFile(BYTE * membuff, int bufflen, char * filename)
{
	FILE * fp = NULL;
	fp = fopen(filename, "wb");

	if(fp == NULL)
	{
		Log(("fopen %s error!", filename));
		return -1;
	}

	if(fwrite(membuff, bufflen, 1, fp) == -1)
	{
		Log(("fwrite %s error!", filename));
		return -1;
	}

	fclose(fp);
	return 0;
}


int FileToMem(char * filename, BYTE * membuff, int bufflen)
{
	FILE * fp = NULL;

	/***检查文件是否存在,不存在则创建文件***/
	if(file_access(filename, F_OK))
	{
		Log(("The %s do not exit,create the file..\n", filename));
		if((fp = fopen(filename, "wb+")) == NULL)
		{
			Log(("fopen %s error ...\n", filename));
			return 1;
		}

		fclose(fp);
	}

	/***检查wakeup文件是否可读***/
	if(file_access(filename, R_OK | W_OK))
	{
		Log(("The %s can not be read ...\n", filename));
		return 1;
	}

	/***读写方式打开2进制文件***/
	if((fp = fopen(filename, "rb+")) == NULL)
	{
		Log(("Open %s error ...\n", filename));
		return 1;
	}

	if(fseek(fp, 0, SEEK_SET) == -1)
	{
		Log((" fseek %s faild\n", filename));
		fclose(fp);
		return 1;
	}

	memset(membuff, 0x0, bufflen);

	if(fread((void *)membuff, bufflen, 1, fp) == -1)
	{
		Log((" fread %s faild!", filename));
		fclose(fp);
		return 1;
	}

	fclose(fp);
	return 0;
}

void Xterm()
{
	system("xterm");
}

void partprobe(char * devname)
{
	char buffer[100];
	memset(buffer, 0, 100);
	sprintf(buffer, "partprobe %s", devname);
	system(buffer);
	Log(("run command: %s", buffer));
}

void umount(char * devname)
{
	char buffer[100];
	memset(buffer, 0, 100);
	sprintf(buffer, "umount %s", devname);
	system(buffer);
	Log(("run command: %s", buffer));
}

int fsystem(const char *fmt, ...)
{
	char cmdbuf[1024] = {0};
	va_list ap;
	va_start(ap, fmt);
	vsprintf(cmdbuf, fmt, ap);
	va_end(ap);
	
	return system(cmdbuf);
}


int delete_file(char * filepath,char * filename)
{
	if(filename == NULL)
		return -1;
	
	if(filepath == NULL)
		return fsystem("rm -rf %s",filename);
	else
		return fsystem("rm -rf %s/%s",filepath,filename);
}

void touch(char * filename)
{
	char cmdbuff[256] = {0};
	sprintf(cmdbuff, "touch %s", filename);
	system(cmdbuff);

	bzero(cmdbuff, 256);
	sprintf(cmdbuff, "chmod 777 %s", filename);
	system(cmdbuff);
}

char g_cmd_result[CMD_RESULT_MAX_LEN];
int get_cmd_output(char * cmd,char * output,int outlen)
{
	memset(g_cmd_result, 0, CMD_RESULT_MAX_LEN);

	if(cmd == NULL)
	{
		Log(("Error: Invalid command!"));
		return -1;
	}

	FILE *fstream = NULL;
	fstream = popen(cmd , "r");
	if(fstream == NULL)
	{
		Log(("Error: fstream is NULL!"));
		return -1;
	}

	size_t len = fread(g_cmd_result, sizeof(char), CMD_RESULT_MAX_LEN, fstream);

	if(len >  0)
	{
		g_cmd_result[len - 1] = '\0';
	}

	if(len  == -1)
	{
		pclose(fstream);
		Log(("Error: fread failed!"));
		return -1;
	}

	strncpy(output,g_cmd_result,outlen);
	
	pclose(fstream);
	return  0;
}

int uni2char(CHAR16 uni, unsigned char *out, int boundlen)
{
	if(boundlen < 2)
		return -EINVAL;

	*out++ = uni & 0xff;
	*out++ = uni >> 8;
	return 2;
}

int char2uni(unsigned char *rawstring, CHAR16 *uni,int boundlen)
{
	if(boundlen < 2)
		return -EINVAL;
	
	*uni = (rawstring[1] << 8) | rawstring[0];
	return 2;
}

/****************************************************************************
 * unicode_to_ascii
 *	Turns a string from Unicode into ASCII.
 *	Doesn't do a good job with any characters that are outside the normal
 *	ASCII range, but it's only for debugging...
 ****************************************************************************/
void unicode_to_ascii(char *string, CHAR16 *unicode, int unicode_size)
{
	int i = 0;

	for(i = 0; i < unicode_size; ++i)
	{
		string[i] = (char)(unicode[i]);
	}

	string[unicode_size] = 0x00;
}

void ascii_to_unicode(char *ascii, CHAR16 *utf, int utfmax)
{
	int retval = 0;

	for(retval = 0; *ascii && utfmax > 1; utfmax -= 2, retval += 2)
	{
		*utf++ = *ascii++ & 0x7f;
		//*utf++ = 0;

		//*utf++ = *ascii++ |(*ascii++ << 8) ;
	}
}


/*
 * 20170927 add by zhangsh 规范日志接口，每条日志头会记录时间，文件名和行号，便于分析
*/
int file_line;
char file_name[100];
struct tm *ptimes = NULL;

//获取时间，文件名和行号
void Setflieandline(char *filename, int line)
{
	time_t plogtime;
	time(&plogtime);
	ptimes = gmtime(&plogtime);

	file_line = line;

	if(filename != NULL)
	{
		memset(file_name, 0x00, 100);
		memcpy(file_name, filename, 100);
	}
}

//把信息输出到屏幕，和日志文件中，当日志文件大小超过20M后，自动清空
void print_msg(const char *fmt, ...)
{
	va_list ap;
	FILE *fp;
	char buf[1024] = {0};
	struct stat statbuff;

	char buffer[1024] = {0};
	
	//sprintf_s(buffer,"[%s,%d]",file_name,file_line);
	sprintf(buffer, "[%02d:%02d:%02d %s,%d]", (ptimes->tm_hour) + 8, ptimes->tm_min, ptimes->tm_sec, file_name, file_line);

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	fp = fopen(LOG_FILE_NAME, "a+");

	if(fp == NULL)
		return;

	int fd = fileno(fp);
	fstat(fd, &statbuff);
	
	if(statbuff.st_size > MAX_LOG_SIZE)
	{
		fclose(fp);
		system("rm -rf " LOG_FILE_NAME);
	}
	else
	{
		if(buffer != NULL)
		{
			strcat(buffer, buf);

			if(buffer[strnlen(buffer,1024) - 1] != '\n') //判断结尾是否换行，没有"\n"则自动补上
				strcat(buffer, "\n");

			fputs(buffer, stdout);
			fputs(buffer, fp);
		}

		//fsync(fd);
		fclose(fp);
	}

	va_end(ap);
	return;
}
