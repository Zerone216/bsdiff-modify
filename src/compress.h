#ifndef _COMPRESS_H_
#define _COMPRESS_H_

#include "common.h"
#pragma pack(1)


#pragma pack()

//compression
int lzo_compressbuff(BYTE * buff, int size);
int lzo_decompressbuff(BYTE * buff, int size);
int zstd_compressbuff(BYTE * buff, int size);
int zstd_decompressbuff(BYTE * buff, int size);
int bz2_compressbuff(BYTE * buff, int size);
int bz2_decompressbuff(BYTE * buff, int size);

#endif
