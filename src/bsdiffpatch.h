#ifndef __BS_DIFF_PATCH_H__
#define __BS_DIFF_PATCH_H__

#include <sys/types.h>
#include "common.h"

off_t create_delta_memory(BYTE * oldbuff ,off_t oldsize ,BYTE * newbuff ,off_t newsize ,BYTE * deltabuff,off_t deltasize,BYTE ztype);
off_t apply_patch_memory(BYTE *oldbuff, off_t oldsize,BYTE *patchbuff, off_t patchsize,BYTE *newbuff,off_t newsize,BYTE ztype);
int create_delta_file(char * oldfile,char * newfile,char * deltafile);
int apply_patch_file(char * oldfile,char * deltafile,char * newfile);

#endif
