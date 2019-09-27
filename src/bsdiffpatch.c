/*-
 * Copyright 2003-2005 Colin Percival
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#include <bzlib.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <bzlib.h>
#include "common.h"
#include "compress.h"
#include "minilzo.h"
#include "zstd.h"
#include "bsdiffpatch.h"

int cprlvl = 3;

static off_t offtin(BYTE *buf)
{
	off_t y;

	y=buf[7]&0x7F;
	y=y*256;y+=buf[6];
	y=y*256;y+=buf[5];
	y=y*256;y+=buf[4];
	y=y*256;y+=buf[3];
	y=y*256;y+=buf[2];
	y=y*256;y+=buf[1];
	y=y*256;y+=buf[0];

	if(buf[7]&0x80) y=-y;

	return y;
}

static void split(off_t *I,off_t *V,off_t start,off_t len,off_t h)
{
	off_t i,j,k,x,tmp,jj,kk;

	if(len<16) {
		for(k=start;k<start+len;k+=j) {
			j=1;x=V[I[k]+h];
			for(i=1;k+i<start+len;i++) {
				if(V[I[k+i]+h]<x) {
					x=V[I[k+i]+h];
					j=0;
				};
				if(V[I[k+i]+h]==x) {
					tmp=I[k+j];I[k+j]=I[k+i];I[k+i]=tmp;
					j++;
				};
			};
			for(i=0;i<j;i++) V[I[k+i]]=k+j-1;
			if(j==1) I[k]=-1;
		};
		return;
	};

	x=V[I[start+len/2]+h];
	jj=0;kk=0;
	for(i=start;i<start+len;i++) {
		if(V[I[i]+h]<x) jj++;
		if(V[I[i]+h]==x) kk++;
	};
	jj+=start;kk+=jj;

	i=start;j=0;k=0;
	while(i<jj) {
		if(V[I[i]+h]<x) {
			i++;
		} else if(V[I[i]+h]==x) {
			tmp=I[i];I[i]=I[jj+j];I[jj+j]=tmp;
			j++;
		} else {
			tmp=I[i];I[i]=I[kk+k];I[kk+k]=tmp;
			k++;
		};
	};

	while(jj+j<kk) {
		if(V[I[jj+j]+h]==x) {
			j++;
		} else {
			tmp=I[jj+j];I[jj+j]=I[kk+k];I[kk+k]=tmp;
			k++;
		};
	};

	if(jj>start) split(I,V,start,jj-start,h);

	for(i=0;i<kk-jj;i++) V[I[jj+i]]=kk-1;
	if(jj==kk-1) I[jj]=-1;

	if(start+len>kk) split(I,V,kk,start+len-kk,h);
}

static void qsufsort(off_t *I,off_t *V,BYTE *old,off_t oldsize)
{
	off_t buckets[256];
	off_t i,h,len;

	for(i=0;i<256;i++) buckets[i]=0;
	for(i=0;i<oldsize;i++) buckets[old[i]]++;
	for(i=1;i<256;i++) buckets[i]+=buckets[i-1];
	for(i=255;i>0;i--) buckets[i]=buckets[i-1];
	buckets[0]=0;

	for(i=0;i<oldsize;i++) I[++buckets[old[i]]]=i;
	I[0]=oldsize;
	for(i=0;i<oldsize;i++) V[i]=buckets[old[i]];
	V[oldsize]=0;
	for(i=1;i<256;i++) if(buckets[i]==buckets[i-1]+1) I[buckets[i]]=-1;
	I[0]=-1;

	for(h=1;I[0]!=-(oldsize+1);h+=h) {
		len=0;
		for(i=0;i<oldsize+1;) {
			if(I[i]<0) {
				len-=I[i];
				i-=I[i];
			} else {
				if(len) I[i-len]=-len;
				len=V[I[i]]+1-i;
				split(I,V,i,len,h);
				i+=len;
				len=0;
			};
		};
		if(len) I[i-len]=-len;
	};

	for(i=0;i<oldsize+1;i++) I[V[i]]=i;
}

static off_t matchlen(BYTE *old,off_t oldsize,BYTE *new,off_t newsize)
{
	off_t i;

	for(i=0;(i<oldsize)&&(i<newsize);i++)
		if(old[i]!=new[i]) break;

	return i;
}

static off_t search(off_t *I,BYTE *old,off_t oldsize,
		BYTE *new,off_t newsize,off_t st,off_t en,off_t *pos)
{
	off_t x,y;

	if(en-st<2) {
		x=matchlen(old+I[st],oldsize-I[st],new,newsize);
		y=matchlen(old+I[en],oldsize-I[en],new,newsize);

		if(x>y) {
			*pos=I[st];
			return x;
		} else {
			*pos=I[en];
			return y;
		}
	};

	x=st+(en-st)/2;
	if(memcmp(old+I[x],new,MIN(oldsize-I[x],newsize))<0) {
		return search(I,old,oldsize,new,newsize,x,en,pos);
	} else {
		return search(I,old,oldsize,new,newsize,st,x,pos);
	};
}

static void offtout(off_t x,BYTE *buf)
{
	off_t y;

	if(x<0) y=-x; else y=x;

		buf[0]=y%256;y-=buf[0];
	y=y/256;buf[1]=y%256;y-=buf[1];
	y=y/256;buf[2]=y%256;y-=buf[2];
	y=y/256;buf[3]=y%256;y-=buf[3];
	y=y/256;buf[4]=y%256;y-=buf[4];
	y=y/256;buf[5]=y%256;y-=buf[5];
	y=y/256;buf[6]=y%256;y-=buf[6];
	y=y/256;buf[7]=y%256;

	if(x<0) buf[7]|=0x80;
}


off_t create_delta_memory(BYTE * oldbuff ,off_t oldsize ,BYTE * newbuff ,off_t newsize ,BYTE * deltabuff,off_t deltasize,BYTE ztype)
{
	BYTE *old = oldbuff;
	BYTE *new = newbuff;
	int offset = 0;
	int validsize = 0;
	off_t *I,*V;
	off_t scan,pos,len;
	off_t lastscan,lastpos,lastoffset;
	off_t oldscore,scsc;
	off_t s,Sf,lenf,Sb,lenb;
	off_t overlap,Ss,lens;
	off_t i;
	off_t cblen,dblen,eblen;
	BYTE *cb,*db,*eb;
	BYTE buf[8];
	BYTE header[32];
	
	/* Allocate oldsize+1 bytes instead of oldsize bytes to ensure that we never try to malloc(0) and get a NULL pointer */
	if(((I=malloc((oldsize+1)*sizeof(off_t)))==NULL) ||
		((V=malloc((oldsize+1)*sizeof(off_t)))==NULL)) Log(("Error : malloc"));

	qsufsort(I,V,old,oldsize);
	free(V);
	
	cblen = 0;
	if((cb=malloc((oldsize+1)*sizeof(BYTE))) == NULL) Log(("Error : malloc"));
	memset(cb,0,oldsize+1);
	
	/* Allocate newsize+1 bytes instead of newsize bytes to ensure
		that we never try to malloc(0) and get a NULL pointer */
	if(((db=malloc(newsize+1))==NULL) ||
		((eb=malloc(newsize+1))==NULL)) Log(("Error : malloc"));
	
	dblen=0;
	eblen=0;
	
	/* Create the patch file */
	/* 
	File is
	offset  			length  	Means
	0					32			Header
	32				X				compressed ctrl block
	32+X			Y				compressed diff block
	32+X+Y		Z				compressed extra block 
	*/
	/* 
	Header is
	offset  length  	Means
	0			8	 		headerflag = "BSDIFF40"
	8			8			length of compressed ctrl block
	16		8			length of compressed diff block
	24		8			length of new file 
	*/
	
	memcpy(header,DELTA_FLAG,8);
	offtout(0, header + 8);
	offtout(0, header + 16);
	offtout(newsize, header + 24);
	memcpy(deltabuff+offset,header, 32);
	offset += 32;
	
	/* Compute the differences, writing ctrl as we go */
	scan=0;len=0;
	lastscan=0;lastpos=0;lastoffset=0;
	while(scan<newsize) {
		oldscore=0;

		for(scsc=scan+=len;scan<newsize;scan++) {
			len=search(I,old,oldsize,new+scan,newsize-scan,
					0,oldsize,&pos);

			for(;scsc<scan+len;scsc++)
			if((scsc+lastoffset<oldsize) &&
				(old[scsc+lastoffset] == new[scsc]))
				oldscore++;

			if(((len==oldscore) && (len!=0)) ||
				(len>oldscore+8)) break;

			if((scan+lastoffset<oldsize) &&
				(old[scan+lastoffset] == new[scan]))
				oldscore--;
		};

		if((len!=oldscore) || (scan==newsize)) {
			s=0;Sf=0;lenf=0;
			for(i=0;(lastscan+i<scan)&&(lastpos+i<oldsize);) {
				if(old[lastpos+i]==new[lastscan+i]) s++;
				i++;
				if(s*2-i>Sf*2-lenf) { Sf=s; lenf=i; };
			};

			lenb=0;
			if(scan<newsize) {
				s=0;Sb=0;
				for(i=1;(scan>=lastscan+i)&&(pos>=i);i++) {
					if(old[pos-i]==new[scan-i]) s++;
					if(s*2-i>Sb*2-lenb) { Sb=s; lenb=i; };
				};
			};

			if(lastscan+lenf>scan-lenb) {
				overlap=(lastscan+lenf)-(scan-lenb);
				s=0;Ss=0;lens=0;
				for(i=0;i<overlap;i++) {
					if(new[lastscan+lenf-overlap+i]==
					   old[lastpos+lenf-overlap+i]) s++;
					if(new[scan-lenb+i]==
					   old[pos-lenb+i]) s--;
					if(s>Ss) { Ss=s; lens=i+1; };
				};

				lenf+=lens-overlap;
				lenb-=lens;
			};

			for(i=0;i<lenf;i++)
				db[dblen+i]=new[lastscan+i]-old[lastpos+i];
			for(i=0;i<(scan-lenb)-(lastscan+lenf);i++)
				eb[eblen+i]=new[lastscan+lenf+i];

			dblen+=lenf;
			eblen+=(scan-lenb)-(lastscan+lenf);
			
			offtout(lenf,buf);
			memcpy(cb+cblen,buf,8);
			cblen += 8;
			
			offtout((scan-lenb)-(lastscan+lenf),buf);
			memcpy(cb+cblen,buf, 8);
			cblen += 8;
			
			offtout((pos-lenb)-(lastpos+lenf),buf);
			memcpy(cb+cblen,buf, 8);
			cblen += 8;
			
			lastscan=scan-lenb;
			lastpos=pos-lenb;
			lastoffset=pos-scan;
			
			
		};
	};
	
	Log(("cblen=[%d]",cblen));
	Log(("dblen=[%d]",dblen));
	Log(("eblen=[%d]",eblen));

	unsigned long in_len = 0;
	unsigned long out_len = 0;
	int blocksize100k = 9; // range of blocksize100k: 1~9
	int verbosity = 0;    // range of verbosity: 1~4 ,0:slient
	int workfactor = 0; // range of workfactor: 0~250 ,default value = 30
	BYTE * out = NULL;
	int ret = 0;
	off_t datalen = 32;
	DWORD dataflag = 0;

	in_len = cblen;
	if(cblen > 0)
	{
		out_len = cblen*3;
		out = malloc(out_len);
		
		if(ztype == BZ2)
		{
			ret = BZ2_bzBuffToBuffCompress((char *)out,(unsigned int *)&out_len, (char *)cb,in_len,blocksize100k,verbosity,workfactor);
			if(ret != BZ_OK)
			{
				free_null(out);
				Log(("internal error - compression failed: %d\n", ret));
				return 0;
			}
			validsize = out_len;
			Log(("bz2:compress cb [%u] ==> [%u]",in_len,validsize));
		}
		else if(ztype == ZSTD)
		{
			ret = ZSTD_compress(out, out_len, cb,in_len , cprlvl);
			if(ZSTD_isError(ret))
			{
				free_null(out);
				Log(("internal error - compression failed: %d\n", ret));
				return 0;
			}
			validsize = ret;
			Log(("zstd:compress cb [%u] ==> [%u]",in_len,validsize));
		}
		else if(ztype == LZO1X)
		{
			char wrkmem[65536];
			memset(wrkmem, 0, 65536);

			if(lzo_init() != LZO_E_OK)
			{
				free_null(out);
				Log(("internal error - lzo_init  failed !!!\n"));
				Log(("(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n"));
				return 0;
			}
			
			ret = lzo1x_1_compress(cb,in_len,out,&out_len, wrkmem);
			if(ret != LZO_E_OK)
			{
				free_null(out);
				Log(("internal error - compression failed: %d\n", ret));
				return 0;
			}
			validsize = out_len;
			Log(("lzo1x:compress cb [%u] ==> [%u]",in_len,validsize));
		}
		
		BYTE * pinbuf = NULL;
		if(validsize >= in_len)
		{
			Log(("invalid compression,use original data,datasize = [%u].",in_len));
			validsize = in_len;
			dataflag = UNCMPRESSED_FLAG;
			pinbuf = cb;
		}
		else
		{
			dataflag = CMPRESSED_FLAG;
			pinbuf = out;
		}

		Log(("cpoffset = [%u],set dataflag = [0x%x]",offset,dataflag));
		memcpy(deltabuff+offset,&dataflag,sizeof(DWORD));
		memcpy(deltabuff+offset+sizeof(DWORD),pinbuf,validsize);
		
		validsize += sizeof(DWORD);
		offset += validsize;
		datalen += validsize;
		free_null(out);
	}

	/* Compute size of compressed ctrl data */
	offtout(validsize, header + 8);
	
	/* Write compressed diff data */
	in_len = dblen;
	if(dblen > 0)
	{
		out_len = dblen*3;
		out = malloc(out_len);
		
		if(ztype == BZ2)
		{
			ret = BZ2_bzBuffToBuffCompress((char *)out,(unsigned int *)&out_len, (char *)db,in_len,blocksize100k,verbosity,workfactor);
			if(ret != BZ_OK)
			{
				free_null(out);
				Log(("internal error - compression failed: %d\n", ret));
				return 0;
			}
			validsize = out_len;
			Log(("bz2:compress db [%u] ==> [%u]",in_len,validsize));
		}
		else if(ztype == ZSTD)
		{
			ret = ZSTD_compress(out,out_len,db,in_len ,cprlvl);
			if(ZSTD_isError(ret))
			{
				free_null(out);
				Log(("internal error - compression failed: %d\n", ret));
				return 0;
			}
			
			validsize = ret;
			Log(("zstd:compress db [%u] ==> [%u]",in_len,validsize));
		}
		else if(ztype == LZO1X)
		{
			char wrkmem[65536];
			memset(wrkmem,0x00,65536);
			if(lzo_init() != LZO_E_OK)
			{
				free_null(out);
				Log(("internal error - lzo_init  failed !!!\n"));
				Log(("(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n"));
				return 0;
			}

			ret = lzo1x_1_compress(db,in_len,out,&out_len, wrkmem);
			if(ret != LZO_E_OK)
			{
				free_null(out);
				Log(("internal error - compression failed: %d\n", ret));
				return 0;
			}
			
			validsize = out_len;
			Log(("lzo1x:compress db [%u] ==> [%u]",in_len,validsize));
		}

		BYTE * pinbuf = NULL;
		if(validsize >= in_len)
		{
			Log(("invalid compression,use original data,datasize = [%u].",in_len));
			validsize = in_len;
			dataflag = UNCMPRESSED_FLAG;
			pinbuf = db;
		}
		else
		{
			dataflag = CMPRESSED_FLAG;
			pinbuf = out;
		}

		Log(("dpoffset = [%u],set dataflag = [0x%x]",offset,dataflag));
		memcpy(deltabuff+offset,&dataflag,sizeof(DWORD));
		memcpy(deltabuff+offset+sizeof(DWORD),pinbuf,validsize);
		
		validsize += sizeof(DWORD);
		offset += validsize;
		datalen += validsize;
		free_null(out);
	}

	/* Compute size of compressed diff data */
	offtout(validsize, header + 16);

	/* Write compressed extra data */
	in_len = eblen;
	if(eblen > 0)
	{
		out_len = eblen*3;
		out = malloc(out_len);

		if(ztype == BZ2)
		{
			ret = BZ2_bzBuffToBuffCompress((char *)out,(unsigned int *)&out_len, (char *)eb,in_len,blocksize100k,verbosity,workfactor);
			if(ret != BZ_OK)
			{
				free_null(out);
				Log(("internal error - compression failed: %d\n", ret));
				return 0;
			}
			validsize = out_len;
			Log(("bz2:compress eb [%u] ==> [%u]",in_len,validsize));
		}
		else if(ztype == ZSTD)
		{
			ret = ZSTD_compress(out,out_len,eb,in_len ,cprlvl);
			if(ZSTD_isError(ret))
			{
				free_null(out);
				Log(("internal error - compression failed: %d\n", ret));
				return 0;
			}
			
			validsize = ret;
			Log(("zstd:compress eb [%u] ==> [%u]",in_len,validsize));
		}
		else if(ztype == LZO1X)
		{
			char wrkmem[65536];
			memset(wrkmem,0x00,65536);
			if(lzo_init() != LZO_E_OK)
			{
					
				free_null(out);
				Log(("internal error - lzo_init  failed !!!\n"));
				Log(("(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n"));
				return 0;
			}
			ret = lzo1x_1_compress(eb,in_len,out,&out_len, wrkmem);
			if(ret != LZO_E_OK)
			{
				free_null(out);
				Log(("internal error - compression failed: %d\n", ret));
				return 0;
			}
			
			validsize = out_len;
			Log(("lzo1x:compress eb [%u] ==> [%u]",in_len,validsize));
		}

		BYTE * pinbuf = NULL;
		if(validsize >= in_len)
		{
			Log(("invalid compression,use original data,datasize = [%u].",in_len));
			validsize = in_len;
			dataflag = UNCMPRESSED_FLAG;
			pinbuf = eb;
		}
		else
		{
			dataflag = CMPRESSED_FLAG;
			pinbuf = out;
		}
		
		Log(("epoffset = [%u],set dataflag = [0x%x]",offset,dataflag));
		memcpy(deltabuff+offset,&dataflag,sizeof(DWORD));
		memcpy(deltabuff+offset+sizeof(DWORD),pinbuf,validsize);
		
		validsize += sizeof(DWORD);
		offset += validsize;
		datalen += validsize;
		free_null(out);
	}

	memcpy(deltabuff,header, 32);/* Seek to the beginning, write the header, and close the file */
	
	/* Free the memory we used */
	free_null(cb);
	free_null(db);
	free_null(eb);
	free_null(I);
	Log(("Generate delta over!"));
	
	return datalen;
}

off_t apply_patch_memory(BYTE *oldbuff, off_t oldsize,BYTE *patchbuff, off_t patchsize,BYTE *newbuff,off_t newsize,BYTE ztype)
{
	off_t cpoffset = 0,dpoffset = 0,epoffset = 0;
	off_t cboffset = 0,dboffset = 0,eboffset = 0;
	ssize_t cbzctrllen,dbzdatalen,ebzdatalen;
	BYTE header[32],buf[8];
	BYTE *old = oldbuff;
	BYTE *new = newbuff;
	BYTE *cb,*db,*eb;
	unsigned long cblen,dblen,eblen;
	off_t oldpos,newpos;
	off_t ctrl[3];
	off_t i = 0,j = 0;

	/* Read header */
	memcpy(header,patchbuff,32);
	
	/* Check for appropriate magic */
	if (memcmp(header, DELTA_FLAG, 8) != 0)
		Log(("Corrupt patch\n"));
	
	/* Read lengths from header */
	cbzctrllen=offtin(header+8);
	Log(("cbzctrllen = [%u]",cbzctrllen));
	dbzdatalen=offtin(header+16);
	Log(("dbzdatalen = [%u]",dbzdatalen));
	ebzdatalen=patchsize-32-cbzctrllen-dbzdatalen;
	Log(("ebzdatalen = [%u]",ebzdatalen));

	newsize=offtin(header+24);
	cpoffset = 32;
	dpoffset = cpoffset + cbzctrllen;
	epoffset = dpoffset + dbzdatalen;
	if((cbzctrllen<0) || (dbzdatalen<0) || (newsize<0))
		Log(("Corrupt patch\n"));
	
	int small = 0;
	int verbosity = 0;
	int ret = 0;
	DWORD dataflag = 0;

	cblen = newsize;
	cb = (BYTE *)malloc(cblen);
	memset(cb,0,cblen);
	
	if(cbzctrllen > 4)
	{
		memcpy(&dataflag,patchbuff+cpoffset,sizeof(DWORD));
		Log(("cpoffset = [%u],get dataflag = [0x%x]",cpoffset,dataflag));
		cbzctrllen -= sizeof(DWORD);
		cpoffset += sizeof(DWORD);
		if(dataflag == CMPRESSED_FLAG)
		{
			if(ztype == BZ2)
			{
				int ret = BZ2_bzBuffToBuffDecompress ((char *)cb,(unsigned int *)&cblen,(char *)patchbuff+cpoffset,cbzctrllen,small,verbosity);
				if(ret != BZ_OK)
				{
					free_null(cb);
					Log(("internal error - decompression failed: %d\n",ret));
					return 0;
				}
				Log(("bz2:decompress cb [%u] ==> [%u]",cbzctrllen,cblen));
			}
			else if(ztype == ZSTD)
			{
				int ret = ZSTD_decompress(cb, cblen, patchbuff+cpoffset,cbzctrllen);
				if(ZSTD_isError(ret))
				{
					free_null(cb);
					Log(("internal error - decompression failed: %d\n",ret));
					return 0;
				}
				cblen = ret;
				Log(("zstd:decompress cblen [%u] ==> [%u]",cbzctrllen,cblen));
			}
			else if(ztype == LZO1X)
			{
				if(lzo_init() != LZO_E_OK)
				{
					free_null(cb);
					Log(("internal error - lzo_init failed !!!\n"));
					Log(("(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n"));
					return 0;
				}

				ret = lzo1x_decompress(patchbuff+cpoffset,cbzctrllen, cb,&cblen, NULL);
				if(ret != LZO_E_OK)
				{
					free_null(cb);
					Log(("internal error - decompression failed: %d\n",ret));
					return 0;
				}
				Log(("lzo1x:decompress cblen [%u] ==> [%u]",cbzctrllen,cblen));
			}
		}
		else
		{
			Log(("uncompressed data,use it directly,datasize = [%u].",cbzctrllen));
			cblen = cbzctrllen;
			memcpy(cb,patchbuff+cpoffset,cblen);
		}
	}
	
	dblen = newsize;
	db = (BYTE *)malloc(dblen);
	memset(db,0,dblen);
	
	if(dbzdatalen > 4)
	{
		memcpy(&dataflag,patchbuff+dpoffset,sizeof(DWORD));
		Log(("dpoffset = [%u],get dataflag = [0x%x]",dpoffset,dataflag));
		dbzdatalen -= sizeof(DWORD);
		dpoffset += sizeof(DWORD);
		if(dataflag == CMPRESSED_FLAG)
		{
		
			if(ztype == BZ2)
			{
				ret = BZ2_bzBuffToBuffDecompress ((char *)db,(unsigned int *)&dblen,(char *)patchbuff+dpoffset,dbzdatalen,small,verbosity);
				if(ret != BZ_OK)
				{
					free_null(db);
					Log(("internal error - decompression failed: %d\n",ret));
					return 0;
				}
				Log(("bz2:decompress db [%u] ==> [%u]",dbzdatalen,dblen));
			}
			else if(ztype == ZSTD)
			{
				ret = ZSTD_decompress(db, dblen, patchbuff+dpoffset,dbzdatalen);
				if(ZSTD_isError(ret))
				{
					free_null(db);
					Log(("internal error - decompression failed: %d\n",ret));
					return 0;
				}
				dblen = ret;
				Log(("zstd:decompress db [%u] ==> [%u]",dbzdatalen,dblen));
				
			}
			else if(ztype == LZO1X)
			{
				if(lzo_init() != LZO_E_OK)
				{
					free_null(db);
					Log(("internal error - lzo_init failed !!!\n"));
					Log(("(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n"));
					return 0;
				}

				ret = lzo1x_decompress(patchbuff+dpoffset,dbzdatalen, db,&dblen, NULL);
				if(ret != LZO_E_OK)
				{
					free_null(db);
					Log(("internal error - decompression failed: %d\n",ret));
					return 0;
				}
				Log(("lzo1x:decompress db [%u] ==> [%u]",dbzdatalen,dblen));
			}
		}
		else
		{
			Log(("uncompressed data,use it directly,datasize = [%u].",dbzdatalen));
			dblen = dbzdatalen;
			memcpy(db,patchbuff+dpoffset,dblen);
		}
	}

	eblen = newsize;
	eb = (BYTE *)malloc(eblen);
	memset(eb,0,eblen);
	
	if(ebzdatalen > 0)
	{
		memcpy(&dataflag,patchbuff+epoffset,sizeof(DWORD));
		Log(("epoffset = [%u],get dataflag = [0x%x]",epoffset,dataflag));
		ebzdatalen -= sizeof(DWORD);
		epoffset += sizeof(DWORD);
		if(dataflag == CMPRESSED_FLAG)
		{
			if(ztype == BZ2)
			{
				ret = BZ2_bzBuffToBuffDecompress ((char *)eb,(unsigned int *)&eblen,(char *)patchbuff+epoffset,ebzdatalen,small,verbosity);
				if(ret != BZ_OK)
				{
					free_null(eb);
					Log(("internal error - decompression failed: %d\n",ret));
					return 0;
				}
				Log(("bz2:decompress eb [%u] ==> [%u]",ebzdatalen,eblen));
			}
			else if(ztype == ZSTD)
			{
				ret = ZSTD_decompress(eb, eblen, patchbuff+epoffset,ebzdatalen);
				if(ZSTD_isError(ret))
				{
					free_null(eb);
					Log(("internal error - decompression failed: %d\n",ret));
					return 0;
				}
				eblen = ret;
				Log(("zstd:decompress eb [%u] ==> [%u]",ebzdatalen,eblen));
				
			}
			else if(ztype == LZO1X)
			{
				if(lzo_init() != LZO_E_OK)
				{
					free_null(eb);
					Log(("internal error - lzo_init failed !!!\n"));
					Log(("(this usually indicates a compiler bug - try recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' for diagnostics)\n"));
					return 0;
				}
				ret = lzo1x_decompress(patchbuff+epoffset,ebzdatalen, eb, &eblen, NULL);
				if(ret != LZO_E_OK)
				{
					free_null(eb);
					Log(("internal error - decompression failed: %d\n",ret));
					return 0;
				}
				Log(("lzo1x:decompress eb [%u] ==> [%u]",ebzdatalen,eblen));
			}
		}
		else
		{
			Log(("uncompressed data,use it directly,datasize = [%u].",ebzdatalen));
			eblen = ebzdatalen;
			memcpy(eb,patchbuff+epoffset,eblen);
		}
	}
	
	oldpos=0;newpos=0;
	while(newpos<newsize)
	{
		/* Read control data */
		for(i=0;i<=2;i++)
		{
			cboffset = 8*i + 24*j;
			memcpy(buf,cb+cboffset,8);
			ctrl[i]=offtin(buf);
		};
		
		/* Sanity-check */
		if(newpos+ctrl[0]>newsize)
			Log(("Corrupt patch\n"));

		/* Read diff string */
		memcpy(new + newpos,db+dboffset,ctrl[0]);
		dboffset += ctrl[0];
		
		/* Add old data to diff string */
		for(i=0;i<ctrl[0];i++)
			if((oldpos+i>=0) && (oldpos+i<oldsize))
				new[newpos+i]+=old[oldpos+i];

		/* Adjust pointers */
		newpos+=ctrl[0];
		oldpos+=ctrl[0];

		/* Sanity-check */
		if(newpos+ctrl[1]>newsize)
			errx(1,"Corrupt patch\n");

		/* Read extra string */
		memcpy(new + newpos,eb+eboffset,ctrl[1]);
		eboffset += ctrl[1];
		
		/* Adjust pointers */
		newpos+=ctrl[1];
		oldpos+=ctrl[2];
		
		j ++;
	};
	
	free_null(cb);
	free_null(db);
	free_null(eb);
	
	Log(("Apply patch over!"));
	
	return newsize;
}


int create_delta_file(char * oldfile,char * newfile,char * deltafile)
{
	int fd;
	BYTE *old,*new;
	off_t oldsize,newsize;
	off_t *I,*V;
	off_t scan,pos,len;
	off_t lastscan,lastpos,lastoffset;
	off_t oldscore,scsc;
	off_t s,Sf,lenf,Sb,lenb;
	off_t overlap,Ss,lens;
	off_t i;
	off_t dblen,eblen;
	BYTE *db,*eb;
	BYTE buf[8]={0};
	BYTE header[32]={0};
	FILE * pf;
	BZFILE * pfbz2;
	int bz2err;
	
	/* Allocate oldsize+1 bytes instead of oldsize bytes to ensure
		that we never try to malloc(0) and get a NULL pointer */
	if(((fd=open(oldfile,O_RDONLY,0))<0) ||
		((oldsize=lseek(fd,0,SEEK_END))==-1) ||
		((old=malloc(oldsize+1))==NULL) ||
		(lseek(fd,0,SEEK_SET)!=0) ||
		(read(fd,old,oldsize)!=oldsize) ||
		(close(fd)==-1)) err(1,"%s",oldfile);

	if(((I=malloc((oldsize+1)*sizeof(off_t)))==NULL) ||
		((V=malloc((oldsize+1)*sizeof(off_t)))==NULL)) err(1,NULL);

	qsufsort(I,V,old,oldsize);

	free(V);

	/* Allocate newsize+1 bytes instead of newsize bytes to ensure
		that we never try to malloc(0) and get a NULL pointer */
	if(((fd=open(newfile,O_RDONLY,0))<0) ||
		((newsize=lseek(fd,0,SEEK_END))==-1) ||
		((new=malloc(newsize+1))==NULL) ||
		(lseek(fd,0,SEEK_SET)!=0) ||
		(read(fd,new,newsize)!=newsize) ||
		(close(fd)==-1)) err(1,"%s",newfile);
	
	Log(("oldsize=[%d]",oldsize));
	Log(("newsize=[%d]",newsize));
	
	if(((db=malloc(newsize+1))==NULL) ||
		((eb=malloc(newsize+1))==NULL)) err(1,NULL);
	dblen=0;
	eblen=0;

	/* Create the patch file */
	if ((pf = fopen(deltafile, "w")) == NULL)
		err(1, "%s", deltafile);

	/* Create the patch file */
	/* 
	File is
	offset  			length  	Means
	0					32			Header
	32				X				compressed ctrl block
	32+X			Y				compressed diff block
	32+X+Y		Z				compressed extra block 
	*/
	/* 
	Header is
	offset  length  	Means
	0			8	 		headerflag = "BSDIFF40"
	8			8			length of compressed ctrl block
	16		8			length of compressed diff block
	24		8			length of new file 
	*/
	
	memcpy(header,DELTA_FLAG,8);
	offtout(0, header + 8);
	offtout(0, header + 16);
	offtout(newsize, header + 24);
	if (fwrite(header, 32, 1, pf) != 1)
		err(1, "fwrite(%s)", deltafile);

	/* Compute the differences, writing ctrl as we go */
	if ((pfbz2 = BZ2_bzWriteOpen(&bz2err, pf, 9, 0, 0)) == NULL)
		errx(1, "BZ2_bzWriteOpen, bz2err = %d", bz2err);
	scan=0;len=0;
	lastscan=0;lastpos=0;lastoffset=0;
	while(scan<newsize) {
		oldscore=0;

		for(scsc=scan+=len;scan<newsize;scan++) {
			len=search(I,old,oldsize,new+scan,newsize-scan,
					0,oldsize,&pos);

			for(;scsc<scan+len;scsc++)
			if((scsc+lastoffset<oldsize) &&
				(old[scsc+lastoffset] == new[scsc]))
				oldscore++;

			if(((len==oldscore) && (len!=0)) ||
				(len>oldscore+8)) break;

			if((scan+lastoffset<oldsize) &&
				(old[scan+lastoffset] == new[scan]))
				oldscore--;
		};

		if((len!=oldscore) || (scan==newsize)) {
			s=0;Sf=0;lenf=0;
			for(i=0;(lastscan+i<scan)&&(lastpos+i<oldsize);) {
				if(old[lastpos+i]==new[lastscan+i]) s++;
				i++;
				if(s*2-i>Sf*2-lenf) { Sf=s; lenf=i; };
			};

			lenb=0;
			if(scan<newsize) {
				s=0;Sb=0;
				for(i=1;(scan>=lastscan+i)&&(pos>=i);i++) {
					if(old[pos-i]==new[scan-i]) s++;
					if(s*2-i>Sb*2-lenb) { Sb=s; lenb=i; };
				};
			};

			if(lastscan+lenf>scan-lenb) {
				overlap=(lastscan+lenf)-(scan-lenb);
				s=0;Ss=0;lens=0;
				for(i=0;i<overlap;i++) {
					if(new[lastscan+lenf-overlap+i]==
					   old[lastpos+lenf-overlap+i]) s++;
					if(new[scan-lenb+i]==
					   old[pos-lenb+i]) s--;
					if(s>Ss) { Ss=s; lens=i+1; };
				};

				lenf+=lens-overlap;
				lenb-=lens;
			};

			for(i=0;i<lenf;i++)
				db[dblen+i]=new[lastscan+i]-old[lastpos+i];
			for(i=0;i<(scan-lenb)-(lastscan+lenf);i++)
				eb[eblen+i]=new[lastscan+lenf+i];

			dblen+=lenf;
			eblen+=(scan-lenb)-(lastscan+lenf);
			Log(("dblen=[%d]",dblen));
			Log(("eblen=[%d]",eblen));
			
			Log(("buf=[%X]",lenf));
			offtout(lenf,buf);
			BZ2_bzWrite(&bz2err, pfbz2, buf, 8);
			if (bz2err != BZ_OK)
				errx(1, "BZ2_bzWrite, bz2err = %d", bz2err);
			
			Log(("buf=[%X]",(scan-lenb)-(lastscan+lenf)));
			offtout((scan-lenb)-(lastscan+lenf),buf);
			BZ2_bzWrite(&bz2err, pfbz2, buf, 8);
			if (bz2err != BZ_OK)
				errx(1, "BZ2_bzWrite, bz2err = %d", bz2err);
			
			Log(("buf=[%X]",(pos-lenb)-(lastpos+lenf)));
			offtout((pos-lenb)-(lastpos+lenf),buf);
			BZ2_bzWrite(&bz2err, pfbz2, buf, 8);
			if (bz2err != BZ_OK)
				errx(1, "BZ2_bzWrite, bz2err = %d", bz2err);
			
			lastscan=scan-lenb;
			lastpos=pos-lenb;
			lastoffset=pos-scan;
		};
	};
	BZ2_bzWriteClose(&bz2err, pfbz2, 0, NULL, NULL);
	if (bz2err != BZ_OK)
		errx(1, "BZ2_bzWriteClose, bz2err = %d", bz2err);
	
	Log(("dblen=[%d]",dblen));
	Log(("eblen=[%d]",eblen));
	
	/* Compute size of compressed ctrl data */
	if ((len = ftello(pf)) == -1)
		err(1, "ftello");
	offtout(len-32, header + 8);
	Log(("len=[%d]",len));
	
	/* Write compressed diff data */
	if ((pfbz2 = BZ2_bzWriteOpen(&bz2err, pf, 9, 0, 0)) == NULL)
		errx(1, "BZ2_bzWriteOpen, bz2err = %d", bz2err);
	MemToFile(db, dblen,"test/diff");
	
	BZ2_bzWrite(&bz2err, pfbz2, db, dblen);
	if (bz2err != BZ_OK)
		errx(1, "BZ2_bzWrite, bz2err = %d", bz2err);
	BZ2_bzWriteClose(&bz2err, pfbz2, 0, NULL, NULL);
	if (bz2err != BZ_OK)
		errx(1, "BZ2_bzWriteClose, bz2err = %d", bz2err);

	/* Compute size of compressed diff data */
	if ((newsize = ftello(pf)) == -1)
		err(1, "ftello");
	offtout(newsize - len, header + 16);
	Log(("dlen=[%d]",newsize - len));
	
	/* Write compressed extra data */
	if ((pfbz2 = BZ2_bzWriteOpen(&bz2err, pf, 9, 0, 0)) == NULL)
		errx(1, "BZ2_bzWriteOpen, bz2err = %d", bz2err);
	
	MemToFile(eb, eblen,"test/extra");
	BZ2_bzWrite(&bz2err, pfbz2, eb, eblen);
	if (bz2err != BZ_OK)
		errx(1, "BZ2_bzWrite, bz2err = %d", bz2err);
	BZ2_bzWriteClose(&bz2err, pfbz2, 0, NULL, NULL);
	if (bz2err != BZ_OK)
		errx(1, "BZ2_bzWriteClose, bz2err = %d", bz2err);

	/* Seek to the beginning, write the header, and close the file */
	if (fseeko(pf, 0, SEEK_SET))
		err(1, "fseeko");
	if (fwrite(header, 32, 1, pf) != 1)
		err(1, "fwrite(%s)", deltafile);
	if (fclose(pf))
		err(1, "fclose");

	/* Free the memory we used */
	free(db);
	free(eb);
	free(I);
	free(old);
	free(new);

	return 0;
}

int apply_patch_file(char * oldfile,char * deltafile,char * newfile)
{
	FILE * f, * cpf, * dpf, * epf;
	BZFILE * cpfbz2, * dpfbz2, * epfbz2;
	int cbz2err, dbz2err, ebz2err;
	int fd;
	ssize_t oldsize,newsize;
	ssize_t bzctrllen,bzdatalen;
	BYTE header[32],buf[8];
	BYTE *old, *new;
	off_t oldpos,newpos;
	off_t ctrl[3];
	off_t lenread;
	off_t i;
	
	/* Open patch file */
	if ((f = fopen(deltafile, "r")) == NULL)
		err(1, "fopen(%s)", deltafile);

	/*
	File format:
		0	8	"BSDIFF40"
		8	8	X
		16	8	Y
		24	8	sizeof(newfile)
		32	X	bzip2(control block)
		32+X	Y	bzip2(diff block)
		32+X+Y	???	bzip2(extra block)
	with control block a set of triples (x,y,z) meaning "add x bytes
	from oldfile to x bytes from the diff block; copy y bytes from the
	extra block; seek forwards in oldfile by z bytes".
	*/

	/* Read header */
	if (fread(header, 1, 32, f) < 32) {
		if (feof(f))
			errx(1, "Corrupt patch\n");
		err(1, "fread(%s)", deltafile);
	}

	/* Check for appropriate magic */
	if (memcmp(header,DELTA_FLAG, 8) != 0)
		errx(1, "Corrupt patch\n");

	/* Read lengths from header */
	bzctrllen=offtin(header+8);
	bzdatalen=offtin(header+16);
	newsize=offtin(header+24);
	
	if((bzctrllen<0) || (bzdatalen<0) || (newsize<0))
		errx(1,"Corrupt patch\n");

	/* Close patch file and re-open it via libbzip2 at the right places */
	if (fclose(f))
		err(1, "fclose(%s)", deltafile);
	
	if ((cpf = fopen(deltafile, "r")) == NULL)
		err(1, "fopen(%s)", deltafile);
	if (fseeko(cpf, 32, SEEK_SET))
		err(1, "fseeko(%s, %lld)", deltafile,
		    (long long)32);
	if ((cpfbz2 = BZ2_bzReadOpen(&cbz2err, cpf, 0, 0, NULL, 0)) == NULL)
		errx(1, "BZ2_bzReadOpen, bz2err = %d", cbz2err);
	
	if ((dpf = fopen(deltafile, "r")) == NULL)
		err(1, "fopen(%s)", deltafile);
	if (fseeko(dpf, 32 + bzctrllen, SEEK_SET))
		err(1, "fseeko(%s, %lld)", deltafile,
		    (long long)(32 + bzctrllen));
	if ((dpfbz2 = BZ2_bzReadOpen(&dbz2err, dpf, 0, 0, NULL, 0)) == NULL)
		errx(1, "BZ2_bzReadOpen, bz2err = %d", dbz2err);
	
	if ((epf = fopen(deltafile, "r")) == NULL)
		err(1, "fopen(%s)", deltafile);
	if (fseeko(epf, 32 + bzctrllen + bzdatalen, SEEK_SET))
		err(1, "fseeko(%s, %lld)", deltafile,
		    (long long)(32 + bzctrllen + bzdatalen));
	if ((epfbz2 = BZ2_bzReadOpen(&ebz2err, epf, 0, 0, NULL, 0)) == NULL)
		errx(1, "BZ2_bzReadOpen, bz2err = %d", ebz2err);

	if(((fd=open(oldfile,O_RDONLY,0))<0) ||
		((oldsize=lseek(fd,0,SEEK_END))==-1) ||
		((old=malloc(oldsize+1))==NULL) ||
		(lseek(fd,0,SEEK_SET)!=0) ||
		(read(fd,old,oldsize)!=oldsize) ||
		(close(fd)==-1)) err(1,"%s",oldfile);
	if((new=malloc(newsize+1))==NULL) err(1,NULL);

	oldpos=0;newpos=0;
	while(newpos<newsize) {
		/* Read control data */
		for(i=0;i<=2;i++) {
			lenread = BZ2_bzRead(&cbz2err, cpfbz2, buf, 8);
			if ((lenread < 8) || ((cbz2err != BZ_OK) &&
			    (cbz2err != BZ_STREAM_END)))
				errx(1, "Corrupt patch\n");
			ctrl[i]=offtin(buf);
			Log(("buf=[%X]",ctrl[i]));
		};

		/* Sanity-check */
		if(newpos+ctrl[0]>newsize)
			errx(1,"Corrupt patch\n");

		/* Read diff string */
		lenread = BZ2_bzRead(&dbz2err, dpfbz2, new + newpos, ctrl[0]);
		if ((lenread < ctrl[0]) ||
		    ((dbz2err != BZ_OK) && (dbz2err != BZ_STREAM_END)))
			errx(1, "Corrupt patch\n");

		/* Add old data to diff string */
		for(i=0;i<ctrl[0];i++)
			if((oldpos+i>=0) && (oldpos+i<oldsize))
				new[newpos+i]+=old[oldpos+i];

		/* Adjust pointers */
		newpos+=ctrl[0];
		oldpos+=ctrl[0];

		/* Sanity-check */
		if(newpos+ctrl[1]>newsize)
			errx(1,"Corrupt patch\n");

		/* Read extra string */
		lenread = BZ2_bzRead(&ebz2err, epfbz2, new + newpos, ctrl[1]);
		if ((lenread < ctrl[1]) ||
		    ((ebz2err != BZ_OK) && (ebz2err != BZ_STREAM_END)))
			errx(1, "Corrupt patch\n");
		
		/* Adjust pointers */
		newpos+=ctrl[1];
		oldpos+=ctrl[2];
	};

	/* Clean up the bzip2 reads */
	BZ2_bzReadClose(&cbz2err, cpfbz2);
	BZ2_bzReadClose(&dbz2err, dpfbz2);
	BZ2_bzReadClose(&ebz2err, epfbz2);
	if (fclose(cpf) || fclose(dpf) || fclose(epf))
		err(1, "fclose(%s)", deltafile);

	/* Write the new file */
	if(((fd=open(newfile,O_CREAT|O_TRUNC|O_WRONLY,0666))<0) ||
		(write(fd,new,newsize)!=newsize) || (close(fd)==-1))
		err(1,"%s",newfile);

	free(new);
	free(old);

	return newsize;
}

