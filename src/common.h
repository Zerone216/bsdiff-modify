#ifndef _COMMON_H_
#define _COMMON_H_

#include <time.h>
#include <sys/types.h>

#define PNULL(p) ((p == NULL)?(1):(0))

#define NO 0
#define YES 1

extern char netdevname[32];
#define NETDEVICE_NAME netdevname

#define CMD_RESULT_MAX_LEN 10240

#define get_cmd_result(cmd)   ((system(cmd) == 0) ? SUCCEED : FAILED

#define FAILED 0
#define SUCCEED 1

#define DELTA_FLAG "BSDIFF40"

#define BZ2 0x01
#define ZSTD 0x02
#define LZO1X 0x03

#define UNCMPRESSED_FLAG 0x55aa55aa 
#define CMPRESSED_FLAG 0x77ee77ee 

typedef u_int8_t  BYTE;
typedef BYTE u8;
typedef u_int16_t WORD;
typedef WORD CHAR16;
typedef u_int32_t DWORD;
typedef u_int64_t DDWORD;

typedef unsigned long long ULONGLONG;
typedef long long LONGLONG;
typedef unsigned long ULONG;
typedef BYTE* LPBYTE;
typedef DWORD UINT;
typedef WORD USHORT;
typedef BYTE* LPSTR;
typedef unsigned char TCHAR;
typedef long long __int64;
typedef WORD* LPWORD;
typedef BYTE BOOL;

#define MIN(x,y) (((x)<(y)) ? (x) : (y))
#define MAX(x,y) (((x)>(y)) ? (x) : (y))

#define _XFF(t) ((t)&0xFF)

#define DEPR_VER(x) \
    _XFF((x)[3]),_XFF((x)[2]),_XFF((x)[1]),_XFF((x)[0])

#define SNIF_GUID(p)     \
    _XFF((p)[3]),_XFF((p)[2]),_XFF((p)[1]),_XFF((p)[0]),_XFF((p)[5]),_XFF((p)[4]),_XFF((p)[7]),_XFF((p)[6]),_XFF((p)[8]),_XFF((p)[9]),_XFF((p)[10]),_XFF((p)[11]),_XFF((p)[12]),_XFF((p)[13]),_XFF((p)[14]),_XFF((p)[15])

#define SNIF_ARR(p)     \
    _XFF((p)[7]),_XFF((p)[6]),_XFF((p)[5]),_XFF((p)[4]),_XFF((p)[3]),_XFF((p)[2]),_XFF((p)[1]),_XFF((p)[0])

#define Auto_trans_unit(x) ((x) > (1024*1024*1024) ?  "GB" : ((x) > (1024*1024) ? "MB" :((x) > 1024 ? "KB" : "B" )))
double Auto_trans_size(DDWORD x);

DDWORD get_file_size(char * filename);
int file_access(const char * filename, int mode);
int free_null(void *p);
int delete_file(char * filepath,char * filename);

#define MAX_LOG_SIZE 20971520	//20M
#define LOG_FILE_NAME "printmsg.log"

void printmsg(const char *fmt, ...);
int uni2char(CHAR16 uni, unsigned char *out, int boundlen);
void unicode_to_ascii(char *string, CHAR16 *unicode, int unicode_size);
void ascii_to_unicode(char *ascii, CHAR16 *utf, int utfmax);

void RemoveChar(char * string, char cas);
void MoveToChar(char cas, char * string);
void StringSplite(char * string, char cfs, char strarr[][5]);
void IpstrToArray(char * ipstr, BYTE * iparray);
char * itoa(int num, char*str, int radix);
void Xterm();
void touch(char * filename);
int MemToFile(BYTE * membuff, int bufflen, char * filename);
int FileToMem(char * filename, BYTE * membuff, int bufflen);
void partprobe(char * devname);
void umount(char * devname);
int fsystem(const char *fmt, ...);
int get_cmd_output(char * cmd,char * output,int outlen);
void print_msg(const char *fmt, ...);
void Setflieandline(char *filename, int line);

//新的日志接口（替换原有的printmsg），使用方法(注意括号为两层)例:Log(("expression error!")); 或者Log(("data1 = %d",data1));
#define Log(Expression)  ({Setflieandline(__FILE__,__LINE__);print_msg Expression;})

#endif
