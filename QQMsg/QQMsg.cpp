// msg.cpp : Defines the entry point for the console application.
//

/*
 *
 * QQmsg.c: Dump QQ message
 *
 * QUQU<quhongjun@msn.com>
 * 2006/12/27
 *
 */


#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <map>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <AFXPRIV.H>
#include <windows.h>
#include <ole2.h>
#include "winsock2.h"
#else
#include <unicode/ucnv.h>
typedef uint32_t ULONG;
typedef unsigned char byte;
#define STGTY_STORAGE 1
#define STGTY_STREAM 2
#endif

#include "tree.h"
#include "md5.h"
#include "QQMsgEx.h"

#ifdef _WIN32
#pragma comment(lib, "ole32.lib" )
#pragma comment(lib, "ws2_32.lib")
#endif

TNode Tree, *TParent;
char pMsgExKey[16];
int iMsgType = 0;
FILE *fpout=NULL;
extern unsigned int Key4;
extern unsigned int Key3;
extern unsigned int Key2;
extern unsigned int Key1;

#ifdef _WIN32
enum {
	CFB_FREESECT = -1,
	CFB_ENDOFCHAIN = -2,
	CFB_FATSECT = -3,
	CFB_DIFSECT = -4
};
#endif

#ifndef _WIN32
static bool MsgEx_ConvertToUtf8(const char *encoding, const char *input, size_t input_len, std::string *output)
{
	UErrorCode status = U_ZERO_ERROR;
	int32_t needed;
	int32_t written;

	needed = ucnv_convert("UTF-8", encoding, NULL, 0, input, (int32_t)input_len, &status);
	if(status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status))
		return false;

	output->resize(needed > 0 ? needed : 0);
	status = U_ZERO_ERROR;
	written = ucnv_convert("UTF-8", encoding, &(*output)[0], needed, input, (int32_t)input_len, &status);
	if(U_FAILURE(status))
		return false;

	output->resize(written);
	return true;
}

static bool MsgEx_ConvertEncoding(const char *to_encoding, const char *from_encoding, const char *input, size_t input_len, std::string *output)
{
	UErrorCode status = U_ZERO_ERROR;
	int32_t needed;
	int32_t written;

	needed = ucnv_convert(to_encoding, from_encoding, NULL, 0, input, (int32_t)input_len, &status);
	if(status != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(status))
		return false;

	output->resize(needed > 0 ? needed : 0);
	status = U_ZERO_ERROR;
	written = ucnv_convert(to_encoding, from_encoding, &(*output)[0], needed, input, (int32_t)input_len, &status);
	if(U_FAILURE(status))
		return false;

	output->resize(written);
	return true;
}

static std::string MsgEx_GbkToUtf8(const char *input, size_t input_len)
{
	std::string output;

	if(input == NULL || input_len == 0)
		return std::string();
	if(MsgEx_ConvertToUtf8("GB18030", input, input_len, &output))
		return output;
	if(MsgEx_ConvertToUtf8("GBK", input, input_len, &output))
		return output;
	if(MsgEx_ConvertToUtf8("CP936", input, input_len, &output))
		return output;
	return std::string(input, input_len);
}

static std::string MsgEx_Utf8ToGbk(const std::string &input)
{
	std::string output;

	if(input.empty())
		return std::string();
	if(MsgEx_ConvertEncoding("GB18030", "UTF-8", input.data(), input.size(), &output))
		return output;
	if(MsgEx_ConvertEncoding("GBK", "UTF-8", input.data(), input.size(), &output))
		return output;
	return input;
}
#endif

char *strtime(time_t *time)
{
	struct tm *tm;
	static char s[80];

	tm = localtime(time);
	if(tm == NULL){
		snprintf(s, sizeof(s), "(TIME=0x%X)", *(int*)time);
		return s;
	}
	snprintf(s, sizeof(s), "%04d-%02d-%02d %02d:%02d:%02d", 
		tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, 
		tm->tm_hour, tm->tm_min, tm->tm_sec);

	return s;

}


/*
struct RecordStruct{
	int time;
	unsigned char type;
	int nameLen;
};
*/
int MsgEx_ShowMsg(char *pOut, int retLen)
{
	char *pName, *pMsg, *pOffset;;
	int msgType=0, nameLen=0, msgLen=0;
	char *strTime;
	time_t t;
	int offset=0;

	if(pOut == NULL || retLen <= 0)
		return -1;

	//time
	offset = 0;
	if(offset + 4 > retLen)
		return -1;
	pOffset = pOut;	//time
	t = *(int*)pOffset;
	strTime = strtime(&t);

		//msgtype
		offset += 4;	//bypass time
		if(offset + 1 > retLen)
			return -1;
		pOffset = pOut+offset;
		msgType = *(char*)pOffset;

		switch(iMsgType)
		{
		case QQEX_MSGTYPE_C2CMSG:
		case QQEX_MSGTYPE_MOBILEMSG:
			offset += 1;	//bypass type
			break;
		case QQEX_MSGTYPE_SYSMSG:
		case QQEX_MSGTYPE_TEMPSESSIONMSG:
			offset += 4;
			break;
		case QQEX_MSGTYPE_GROUPMSG:
			{
			if(offset + 8 > retLen)
				return -1;
			int from=*(int*)pOffset;
			int to=*(int*)(pOffset+4);
			offset += 8;
			break;
			}
		case QQEX_MSGTYPE_DISCMSG:
			offset += 1;	//bypass type=1
			offset += 4;	//bypass unknown
			offset += 8;	//bypass from, to
			break;
		case QQEX_MSGTYPE_IMINFO:
		default:
			offset += 1;	//bypass type
			break;
		}
		if(offset + 4 > retLen)
			return -1;
		pOffset = pOut+offset;

		//nameLen
		nameLen = *(int*)pOffset;
		if(nameLen <= 0 || nameLen > (retLen-offset-4)){
			//printf("nameLen overflow 0x(%x), iMsgtype=%d\n", nameLen, iMsgType);
			return -1;
		}

		//name
		offset += 4;	//bypass nameLen
		pOffset = pOut+offset;
		if(offset > retLen){
			//printf("offset overflow\n");
			return -1;
		}
		pName = pOffset;

		//msgLen
		offset += nameLen;	//bypass name, now points to recordLen
		if(offset + 4 > retLen){
			//printf("offset overflow\n");
			return -1;
		}
		pOffset = pOut+offset;
		msgLen = *(int*)(pOffset);
		if(msgLen <= 0 || msgLen > (retLen-offset-4)){
			//printf("msgLen overflow (0x%x)\n", msgLen);
			return -1;
		}

		*(pName+nameLen) = 0x0;		//this will overwrite msgLen, so put it afterward

		//msg
		offset += 4;	//bypass msgLen, now points to msg
		pOffset = pOut + offset;
		if(offset > retLen || offset + msgLen > retLen){
			//printf("offset overflow\n");
			return -1;
		}
		pMsg = pOffset;

		//throw font message
		{
			char *p = pMsg;
			while(p < (pOut+retLen) && *p)
			{
				if((p + 1 < (pOut+retLen)) && ((*p)==0x13) && ((*(p+1))==0x15)){
					*p = 0x0;
					break;
				}
				p++;
			}
		}
		fprintf(fpout, "%s ", strTime);
#ifdef _WIN32
		fprintf(fpout, "%s\n", pName);
		fprintf(fpout, "%s\n\n", pMsg);
#else
		{
			size_t msgTextLen = strnlen(pMsg, msgLen);
			std::string utf8Name = MsgEx_GbkToUtf8(pName, nameLen);
			std::string utf8Msg = MsgEx_GbkToUtf8(pMsg, msgTextLen);
			fprintf(fpout, "%s\n", utf8Name.c_str());
			fprintf(fpout, "%s\n\n", utf8Msg.c_str());
		}
#endif

	
	return 0;
}


int MsgEx_DecodeMsg(char *pData, char *pIndex, ULONG dSize, ULONG iSize)
{
	int nRecord=0;
	unsigned int Offset=0, lastOffset=0, nextOffset=0;
	unsigned int RecordLen=0;
	int i;
	char *pIn;
	char pOut[MAX_MSG_LEN];
	int *p;
	int retLen=0;
	int ret=0;

	memset(pOut, 0, MAX_MSG_LEN);

	nRecord = iSize/4;
	
//	printf("Decoding %d records ..\n", nRecord);
	lastOffset = 0;
	for(i=0; i<nRecord; i++){
		p = (int*)(pIndex + i*4);
		Offset = *(int *)p;
		if(i == (nRecord-1))
			nextOffset = dSize;
		else
			nextOffset = *(int*)(p+1);
//		printf("\tRecord[%d]: Offset=%d\n", i, Offset);
		RecordLen = nextOffset - Offset;
		pIn = pData + Offset;
		retLen = RecordLen;
		memset(pOut, 0, sizeof(pOut));
		lastOffset = Offset;
		ret = QQMSG_decode(pIn, RecordLen, pMsgExKey, pOut, &retLen);
		if(ret < 0){
			printf("Decoding message #%d failed!\n", i);
			continue;
		}

//		printf("%d bytes decoded\n", retLen);
//		MsgEx_DumpHex(pOut, retLen);
		MsgEx_ShowMsg(pOut, retLen);
	}

	return 0;

}


int MsgEx_SetMsgType(char *name)
{

	if(strcmp(name, "C2CMsg") == 0){
		iMsgType = QQEX_MSGTYPE_C2CMSG;
		fprintf(fpout, "\n\n==================================================\n");
		fprintf(fpout, "消息类型：用户消息\n"); 
		fprintf(fpout, "==================================================\n\n");
		return 0;
	}
	if(strcmp(name, "SysMsg") == 0){
		iMsgType = QQEX_MSGTYPE_SYSMSG;
		fprintf(fpout, "\n\n==================================================\n");
		fprintf(fpout, "消息类型：系统消息\n"); 
		fprintf(fpout, "==================================================\n\n");
		return 0;
	}
	if(strcmp(name, "IMInfo") == 0){
		iMsgType = QQEX_MSGTYPE_IMINFO;
		fprintf(fpout, "\n\n==================================================\n");
		fprintf(fpout, "消息类型：IMInfo\n"); 
		fprintf(fpout, "==================================================\n\n");
		return 0;
	}
	if(strcmp(name, "DiscMsg") == 0){
		iMsgType = QQEX_MSGTYPE_DISCMSG;
		fprintf(fpout, "\n\n==================================================\n");
		fprintf(fpout, "消息类型：DiscMsg\n"); 
		fprintf(fpout, "==================================================\n\n");
		return 0;
	}
	if(strcmp(name, "GroupMsg") == 0){
		iMsgType = QQEX_MSGTYPE_GROUPMSG;
		fprintf(fpout, "\n\n==================================================\n");
		fprintf(fpout, "消息类型：群组消息\n"); 
		fprintf(fpout, "==================================================\n\n");
		return 0;
	}
	if(strcmp(name, "MobileMsg") == 0){
		iMsgType = QQEX_MSGTYPE_MOBILEMSG;
		fprintf(fpout, "\n\n==================================================\n");
		fprintf(fpout, "消息类型：移动消息\n"); 
		fprintf(fpout, "==================================================\n\n");
		return 0;
	}
	if(strcmp(name, "TempSessionMsg") == 0){
		iMsgType = QQEX_MSGTYPE_TEMPSESSIONMSG;
		fprintf(fpout, "\n\n==================================================\n");
		fprintf(fpout, "消息类型：临时会话\n"); 
		fprintf(fpout, "==================================================\n\n");
		return 0;
	}

	return 0;
}



int MsgEx_DumpTnodeMsg(TNode *T)
{
	TNode *tData, *tIndex;

	if(!T)
		return -1;

	tData = TNode_find(T, "Data.msj");
	if(!tData)
		return -1;
	tIndex = TNode_find(T, "Index.msj");
	if(!tIndex)
		return -1;

	fprintf(fpout, "--------------------------------------------------\n");
	fprintf(fpout, "消息对象：%s\n", T->name);
	fprintf(fpout, "--------------------------------------------------\n");
	MsgEx_DecodeMsg(tData->data, tIndex->data, tData->len, tIndex->len);
	return 0;
}


int MsgEx_DumpMsg(TNode *T)
{
	TNode *t;

	if(!T)
		return -1;


	if(!T->firstchild)
		return -1;

	MsgEx_SetMsgType(T->name);
	for(t=T->firstchild; t; t=t->nextsibling){
		if(t->type == STGTY_STORAGE){
				MsgEx_DumpMsg(t);
		}else{
			if(strcmp(t->name, "Matrix.db") == 0)
				continue;
			MsgEx_DumpTnodeMsg(T);
			return 0;
		}
	}

	return 0;
}




/*
Matrix.db:
struct MatrixDbRecord{
	char RecordType;
	short nameLen;
	char name[...];
	int RecordLen;
	char Record[...];
};
*/


char * MsgEx_FindMatrixDB(char *pMatrix, int Len, char *name, int *retLen)
{
	char *pLocal;
	unsigned char RecordType;
	unsigned short nameLen;
	char *RecordName;
	unsigned int RecordLen=0;
	char *RecordData=NULL;
	int count = 0;

	pLocal = pMatrix+6;
	count += 6;

	while(count < Len)
	{
		RecordType = *pLocal;
		nameLen = *(short*)(pLocal+1);
		RecordName = pLocal+3;
		RecordLen = *(int*)(pLocal+3+nameLen);
		RecordData = pLocal+3+nameLen+4;
		if(strncmp(RecordName, name, strlen(name)) == 0){
			*retLen = RecordLen;
			return RecordData;
		}
		pLocal += (3+nameLen+4+RecordLen);
		count += (3+nameLen+4+RecordLen);
	}

	*retLen = 0;
	return NULL;
}


int MsgEx_DecodeMatrixDB(char *pIn, int Len)
{
/*
入口：
eax: pMatrixDB
edx: Len

本地变量：
[ebp-4]: char *pIn
[ebp-8]: int *pLen
[ebp-C]: ret
[ebp-10]: i
[ebp-14]: int n;
[ebp-18]: int count=Len
[ebp-1C]: char *pLocal = pIn+6
[ebp-1D]: char charD = rType;
[ebp-1E]: char charE;
[ebp-20]: short nLen
*/
	char *pLocal;
	int i;
	int count = Len;
	char rType;
	char charE;
	short nLen;
	int rLen;

	if(Len > 0x7FFF)
		return -1;
	if(*pIn != 'Q')
		return -1;
	if(*(pIn+1) != 'D')
		return -1;

	pLocal = pIn+6;
	count = Len-6;
	
	while(count > 7)
	{
		short ax;
		char al;
		
		rType = *pLocal;		//0x2
		nLen = (short)*(pLocal+1);	//0x0003
		ax = nLen;
		ax >>= 8;
		al = (char)ax;		//0x0
		al ^= (char)nLen;	//0x0^0x3=3
		charE = al;		//0x3
		pLocal += 3;
		count -= 3;
	
		for(i=0; i<nLen; i++)	//EBP20=0x3
		{
			char *p = pLocal; //0xaf
			char al;
			al = *p;
			al ^= charE;	//0xaf^0x3=0xAC
			al = ~al;	//not 0xac = 0x53
			*p = al;
			pLocal++;
			count--;
		}
		if(rType > 7)
			return -1;
		
		rLen = *(int*)pLocal;	//0x0001
		pLocal += 4;
		count -= 4;
		
		if((rType == 6) || (rType == 7))
		{
			short ax;
			
			ax = (short)rLen;
			ax >>= 8;
			al = (char)ax;
			al ^= (byte)rLen;
			charE = al;
			
			for(i=0; i<rLen; i++){
				char *p = pLocal;
				char al;
				al = (char)*p;
				al ^= charE;
				al = ~al;
				*p = al;
				pLocal++;
				count--;		
			}
			
			continue;
		}
		
		pLocal += rLen;
		continue;
	} //end of while
	
	return 0;
}


#ifdef _WIN32
int MsgEx_OpenSubStream(IStorage *psubStg, LPOLESTR pwcsName, ULONG len, char *pOut)
{
	ULONG nsize=0;
	HRESULT hr;
	IStream *pStm = NULL;
	char *buf=NULL;
	
	if(pOut == NULL)
		return -1;
	
//	wprintf(L"Reading: %s\n", pwcsName);

	hr = psubStg->OpenStream(
		pwcsName, 
		NULL,
		STGM_READ | STGM_SHARE_EXCLUSIVE,
		0,
		&pStm
	);
	
	if(hr != S_OK){
		wprintf(L"Failed to open stream %s, errno:0x%X\n", pwcsName, hr);
		goto out;
	}
	
	hr = pStm->Read(pOut, len, &nsize);
	if(hr != S_OK){
		wprintf(L"Failed to read stream %s, errno:0x%X\n", pwcsName, hr);
		goto out;
	}

//	printf("%lu bytes read\n", nsize);
	//MsgEx_DumpHex(pOut, nsize);
	

out:	
	if( pStm )	pStm->Release();

	return nsize;
}



/* return: &psubStg */
int MsgEx_OpenSubStorage(IStorage *pStg, LPOLESTR pwcsName, IStorage **psubStg) 
{
	HRESULT hr;

		hr = pStg->OpenStorage(
			pwcsName, 
			NULL,
			STGM_READ | STGM_SHARE_EXCLUSIVE,
			0,
			0,
			psubStg);

	if(hr != S_OK){
		wprintf(L"Failed to open %s, errno:0x%X\n", pwcsName, hr);
		return -1;
	}
	
	return 0;
}



int MsgEx_EnumStorage(IStorage *pStg) 
{
	HRESULT hr;
	IStorage *psubStg = NULL;
	IEnumSTATSTG *pEnum=NULL;
	STATSTG statstg;
	ULONG nSize, maxSize=0;
	char *pOut=NULL;
	TNode *t=NULL;
	
	hr = pStg->EnumElements( 0, NULL, 0, &pEnum );
	ASSERT( SUCCEEDED(hr) );

	while( NOERROR == pEnum->Next( 1, &statstg, NULL) )
	{
		int iSize;
		char* pszMultiByte;

		t = TNode_alloc();
		TNODE_INIT((*t));
		TNode_add(TParent, t);

		//convert wide char to multibyte
		iSize = WideCharToMultiByte(CP_ACP, 0, statstg.pwcsName, -1, NULL, 0, NULL, NULL);
		pszMultiByte = (char*)malloc((iSize+1)/**sizeof(char)*/);
		WideCharToMultiByte(CP_ACP, 0, statstg.pwcsName, -1, pszMultiByte, iSize, NULL, NULL);


		nSize = statstg.cbSize.QuadPart;
		t->len = nSize;
		t->type = statstg.type;
		sprintf(t->name, "%s", pszMultiByte);
		if(t->len > 0){
			t->data = (char*)malloc(t->len);
		}


		if(statstg.type == STGTY_STORAGE){
			if(MsgEx_OpenSubStorage(pStg, statstg.pwcsName, &psubStg)>=0){
				TParent = t;
				MsgEx_EnumStorage(psubStg);
				TParent = t->parent;
				if(psubStg) {psubStg->Release(); psubStg=NULL;}
			}
		}else
		if(statstg.type == STGTY_STREAM){
			MsgEx_OpenSubStream(pStg, statstg.pwcsName, t->len, t->data);
		}
		CoTaskMemFree( statstg.pwcsName );
	}


	if( pEnum )	pEnum->Release();
	if( psubStg )	psubStg->Release();
		
	return 0;

}



int MsgEx_OpenStorageFile(char *fname) 
{	
	LPCTSTR lpFileName = _T( fname );
	IStorage *pStg = NULL;
	USES_CONVERSION;
	LPCOLESTR lpwFileName = T2COLE( lpFileName );	// 转换T类型为宽字符
	HRESULT hr;

	hr = StgIsStorageFile( lpwFileName );	// 是复合文件吗？
	if( FAILED(hr) ){
		printf("Invalid QQ message file: %s\n", fname);
		return -1;
	}

	hr = StgOpenStorage(			// 打开复合文件
		lpwFileName,			// 文件名称
		NULL,
		STGM_READ | STGM_SHARE_DENY_WRITE,
		0,
		0,
		&pStg);				// 得到根存储接口指针

	if( FAILED(hr) ){
		printf("Failed to open file %s, errno: 0x%x\n", fname, hr);
		return -1;
	}

	MsgEx_EnumStorage(pStg);


	if( pStg )	pStg->Release();

	return 0;

}
#else
enum {
	CFB_FREESECT = -1,
	CFB_ENDOFCHAIN = -2,
	CFB_FATSECT = -3,
	CFB_DIFSECT = -4,
	CFB_MAXREGSECT = -6
};

struct CfbDirEntry {
	std::string name;
	uint8_t type;
	uint8_t color;
	int32_t left;
	int32_t right;
	int32_t child;
	uint32_t start;
	uint64_t size;
};

struct CfbFile {
	std::vector<unsigned char> bytes;
	uint16_t sector_size;
	uint16_t mini_sector_size;
	uint32_t mini_cutoff;
	int32_t first_dir_sector;
	int32_t first_mini_fat_sector;
	uint32_t num_mini_fat_sectors;
	int32_t first_difat_sector;
	uint32_t num_difat_sectors;
	uint32_t num_fat_sectors;
	std::vector<int32_t> fat;
	std::vector<int32_t> mini_fat;
	std::vector<CfbDirEntry> dirs;
	std::vector<unsigned char> mini_stream;
};

static uint16_t cfb_le16(const unsigned char *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t cfb_le32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t cfb_le64(const unsigned char *p)
{
	return (uint64_t)cfb_le32(p) | ((uint64_t)cfb_le32(p + 4) << 32);
}

static bool cfb_sector_ptr(const CfbFile &cfb, int32_t sid, const unsigned char **out)
{
	if(sid < 0)
		return false;
	uint64_t offset = ((uint64_t)sid + 1) * cfb.sector_size;
	if(offset + cfb.sector_size > cfb.bytes.size())
		return false;
	*out = &cfb.bytes[(size_t)offset];
	return true;
}

static bool cfb_read_regular_chain(const CfbFile &cfb, int32_t start, uint64_t size, std::vector<unsigned char> &out)
{
	int32_t sid = start;
	uint64_t remaining = size;
	size_t guard = 0;

	out.clear();
	while(sid >= 0 && sid != CFB_ENDOFCHAIN) {
		const unsigned char *sector;
		if((size_t)sid >= cfb.fat.size() || !cfb_sector_ptr(cfb, sid, &sector))
			return false;

		size_t n = cfb.sector_size;
		if(size != UINT64_MAX && remaining < n)
			n = (size_t)remaining;
		out.insert(out.end(), sector, sector + n);

		if(size != UINT64_MAX) {
			remaining -= n;
			if(remaining == 0)
				break;
		}

		sid = cfb.fat[(size_t)sid];
		if(++guard > cfb.fat.size())
			return false;
	}
	return size == UINT64_MAX || remaining == 0;
}

static bool cfb_read_mini_chain(const CfbFile &cfb, uint32_t start, uint64_t size, std::vector<unsigned char> &out)
{
	uint32_t sid = start;
	uint64_t remaining = size;
	size_t guard = 0;

	out.clear();
	while((int32_t)sid >= 0 && (int32_t)sid != CFB_ENDOFCHAIN) {
		uint64_t offset = (uint64_t)sid * cfb.mini_sector_size;
		if(offset >= cfb.mini_stream.size() || sid >= cfb.mini_fat.size())
			return false;

		size_t n = cfb.mini_sector_size;
		if(remaining < n)
			n = (size_t)remaining;
		if(offset + n > cfb.mini_stream.size())
			return false;
		out.insert(out.end(), cfb.mini_stream.begin() + (size_t)offset, cfb.mini_stream.begin() + (size_t)offset + n);

		remaining -= n;
		if(remaining == 0)
			break;

		sid = (uint32_t)cfb.mini_fat[sid];
		if(++guard > cfb.mini_fat.size())
			return false;
	}
	return remaining == 0;
}

static std::string cfb_utf16le_name(const unsigned char *entry)
{
	uint16_t name_len = cfb_le16(entry + 64);
	std::string out;
	if(name_len < 2)
		return out;
	if(name_len > 64)
		name_len = 64;
	for(uint16_t i = 0; i + 1 < name_len - 2; i += 2) {
		uint16_t ch = cfb_le16(entry + i);
		out.push_back(ch < 0x80 ? (char)ch : '?');
	}
	return out;
}

static bool cfb_load(const char *fname, CfbFile &cfb)
{
	static const unsigned char magic[8] = {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1};
	FILE *fp = fopen(fname, "rb");
	long fsize;

	if(!fp)
		return false;
	if(fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return false;
	}
	fsize = ftell(fp);
	if(fsize < 512) {
		fclose(fp);
		return false;
	}
	rewind(fp);
	cfb.bytes.resize((size_t)fsize);
	if(fread(&cfb.bytes[0], 1, cfb.bytes.size(), fp) != cfb.bytes.size()) {
		fclose(fp);
		return false;
	}
	fclose(fp);

	if(memcmp(&cfb.bytes[0], magic, sizeof(magic)) != 0)
		return false;

	cfb.sector_size = (uint16_t)(1u << cfb_le16(&cfb.bytes[30]));
	cfb.mini_sector_size = (uint16_t)(1u << cfb_le16(&cfb.bytes[32]));
	cfb.num_fat_sectors = cfb_le32(&cfb.bytes[44]);
	cfb.first_dir_sector = (int32_t)cfb_le32(&cfb.bytes[48]);
	cfb.mini_cutoff = cfb_le32(&cfb.bytes[56]);
	cfb.first_mini_fat_sector = (int32_t)cfb_le32(&cfb.bytes[60]);
	cfb.num_mini_fat_sectors = cfb_le32(&cfb.bytes[64]);
	cfb.first_difat_sector = (int32_t)cfb_le32(&cfb.bytes[68]);
	cfb.num_difat_sectors = cfb_le32(&cfb.bytes[72]);

	if(cfb.sector_size < 512 || cfb.bytes.size() < cfb.sector_size)
		return false;

	std::vector<int32_t> difat;
	for(int i = 0; i < 109; i++) {
		int32_t sid = (int32_t)cfb_le32(&cfb.bytes[76 + i * 4]);
		if(sid >= 0)
			difat.push_back(sid);
	}

	int32_t dif_sid = cfb.first_difat_sector;
	for(uint32_t n = 0; n < cfb.num_difat_sectors && dif_sid >= 0; n++) {
		const unsigned char *sector;
		if(!cfb_sector_ptr(cfb, dif_sid, &sector))
			return false;
		size_t entries = cfb.sector_size / 4 - 1;
		for(size_t i = 0; i < entries; i++) {
			int32_t sid = (int32_t)cfb_le32(sector + i * 4);
			if(sid >= 0)
				difat.push_back(sid);
		}
		dif_sid = (int32_t)cfb_le32(sector + entries * 4);
	}

	for(uint32_t i = 0; i < cfb.num_fat_sectors && i < difat.size(); i++) {
		const unsigned char *sector;
		if(!cfb_sector_ptr(cfb, difat[i], &sector))
			return false;
		for(size_t j = 0; j < cfb.sector_size / 4; j++)
			cfb.fat.push_back((int32_t)cfb_le32(sector + j * 4));
	}

	std::vector<unsigned char> dir_stream;
	if(!cfb_read_regular_chain(cfb, cfb.first_dir_sector, UINT64_MAX, dir_stream))
		return false;
	for(size_t off = 0; off + 128 <= dir_stream.size(); off += 128) {
		const unsigned char *entry = &dir_stream[off];
		CfbDirEntry dir;
		dir.name = cfb_utf16le_name(entry);
		dir.type = entry[66];
		dir.color = entry[67];
		dir.left = (int32_t)cfb_le32(entry + 68);
		dir.right = (int32_t)cfb_le32(entry + 72);
		dir.child = (int32_t)cfb_le32(entry + 76);
		dir.start = cfb_le32(entry + 116);
		dir.size = cfb_le64(entry + 120);
		cfb.dirs.push_back(dir);
	}
	if(cfb.dirs.empty())
		return false;

	if(cfb.num_mini_fat_sectors > 0 && cfb.first_mini_fat_sector >= 0) {
		std::vector<unsigned char> mini_fat_stream;
		if(!cfb_read_regular_chain(cfb, cfb.first_mini_fat_sector, (uint64_t)cfb.num_mini_fat_sectors * cfb.sector_size, mini_fat_stream))
			return false;
		for(size_t off = 0; off + 4 <= mini_fat_stream.size(); off += 4)
			cfb.mini_fat.push_back((int32_t)cfb_le32(&mini_fat_stream[off]));
	}

	if(cfb.dirs[0].size > 0 && cfb.dirs[0].start != (uint32_t)CFB_ENDOFCHAIN)
		cfb_read_regular_chain(cfb, (int32_t)cfb.dirs[0].start, cfb.dirs[0].size, cfb.mini_stream);

	return true;
}

static bool cfb_stream_data(const CfbFile &cfb, const CfbDirEntry &dir, std::vector<unsigned char> &out)
{
	if(dir.size == 0) {
		out.clear();
		return true;
	}
	if(dir.size < cfb.mini_cutoff && !cfb.mini_fat.empty())
		return cfb_read_mini_chain(cfb, dir.start, dir.size, out);
	return cfb_read_regular_chain(cfb, (int32_t)dir.start, dir.size, out);
}

static void cfb_add_tree_children(const CfbFile &cfb, int32_t sid, TNode *parent)
{
	if(sid < 0 || (size_t)sid >= cfb.dirs.size())
		return;

	const CfbDirEntry &dir = cfb.dirs[(size_t)sid];
	cfb_add_tree_children(cfb, dir.left, parent);

	if(dir.type == STGTY_STORAGE || dir.type == STGTY_STREAM) {
		TNode *t = TNode_alloc();
		TNODE_INIT((*t));
		t->type = dir.type;
		t->len = (int)dir.size;
		snprintf(t->name, sizeof(t->name), "%s", dir.name.c_str());
		if(dir.type == STGTY_STREAM && dir.size > 0) {
			std::vector<unsigned char> data;
			if(cfb_stream_data(cfb, dir, data)) {
				t->len = (int)data.size();
				t->data = (char*)malloc(t->len);
				if(t->data)
					memcpy(t->data, &data[0], t->len);
			}
		}
		TNode_add(parent, t);
		if(dir.type == STGTY_STORAGE)
			cfb_add_tree_children(cfb, dir.child, t);
	}

	cfb_add_tree_children(cfb, dir.right, parent);
}

int MsgEx_OpenStorageFile(char *fname)
{
	CfbFile cfb;
	if(!cfb_load(fname, cfb)) {
		printf("Invalid QQ message file: %s\n", fname);
		return -1;
	}
	cfb_add_tree_children(cfb, cfb.dirs[0].child, &Tree);
	return 0;
}
#endif




char *Find_QQPath_Number(char *path, char *retPath, char *pUid)
{
	char *p;
	int pos1=-1, pos2=-1;
	int offset=0;

	offset = strlen(path)-1;

	/* D:\tencent\1234567\ */
	p = path+offset;
	if(isdigit(*p))
	{
		sprintf(retPath, "%s\\MsgEx.db", path);
	}else
	if((*p) == '\\')
	{
		sprintf(retPath, "%sMsgEx.db", path);
	}else
	{
		sprintf(retPath, "%s", path);
	}


	while(offset > 0){
		p = path+offset;
		if(isdigit(*p)){
			pos1 = offset;
			break;
		}
		offset--;
	}

	if(pos1 < 0){
		return NULL;
	}
	offset = pos1;
	while(offset >= 0){
		p = path+offset;
		if(!isdigit(*p))
			break;
		pos2 = offset;
		offset--;
	}

	if(pos2 < 0){
		return NULL;
	}

	p = path+pos2;
	strncpy(pUid, p, pos1-pos2+1);
	return pUid;
}


char *Find_QQNumber(char *path, char *pUid)
{
	char *p;
	int pos1=-1, pos2=-1;
	char buf[20];
	int n=0;
	int offset=0;

	memset(buf, 0, sizeof(buf));
	offset = strlen(path)-1;
	while(offset > 0){
		p = path+offset;
		if(*p == '\\'){
			pos1 = offset;
			break;
		}
		offset--;
	}

	if(pos1 < 0){
		return NULL;
	}
	offset = pos1-1;
	while(offset >= 0){
		p = path+offset;
		if(!isdigit(*p))
			break;
		buf[n] = *p;
		n++;
		pos2 = offset;
		offset--;
	}

	if(pos2 < 0){
		return NULL;
	}

	p = path+pos2;
	strncpy(pUid, p, pos1-pos2);
	return pUid;
}

struct ImportRecord {
	int msg_type;
	std::string object;
	time_t when;
	std::string name;
	std::string msg;
};

struct ImportSection {
	int msg_type;
	std::string object;
	std::vector<ImportRecord> records;
};

struct ImportStream {
	std::string name;
	uint8_t type;
	uint8_t color;
	int left;
	int child;
	int right;
	std::vector<unsigned char> data;
	uint32_t start;
	uint64_t size;
};

static void put_le16(std::vector<unsigned char> &out, uint16_t v)
{
	out.push_back((unsigned char)(v & 0xff));
	out.push_back((unsigned char)((v >> 8) & 0xff));
}

static void put_le32(std::vector<unsigned char> &out, uint32_t v)
{
	out.push_back((unsigned char)(v & 0xff));
	out.push_back((unsigned char)((v >> 8) & 0xff));
	out.push_back((unsigned char)((v >> 16) & 0xff));
	out.push_back((unsigned char)((v >> 24) & 0xff));
}

static void set_le16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
}

static void set_le32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
	p[2] = (unsigned char)((v >> 16) & 0xff);
	p[3] = (unsigned char)((v >> 24) & 0xff);
}

static void set_le64(unsigned char *p, uint64_t v)
{
	set_le32(p, (uint32_t)(v & 0xffffffffu));
	set_le32(p + 4, (uint32_t)(v >> 32));
}

static uint32_t get_be32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)((v >> 24) & 0xff);
	p[1] = (unsigned char)((v >> 16) & 0xff);
	p[2] = (unsigned char)((v >> 8) & 0xff);
	p[3] = (unsigned char)(v & 0xff);
}

static void MsgEx_BlowfishEncryptBlock(const unsigned char *in, const unsigned char *key, unsigned char *out)
{
	unsigned int edx, ebx;

	Key4 = get_be32(key);
	Key3 = get_be32(key + 4);
	Key2 = get_be32(key + 8);
	Key1 = get_be32(key + 12);
	edx = get_be32(in);
	ebx = get_be32(in + 4);
	Encrypt(&edx, &ebx);
	put_be32(out, edx);
	put_be32(out + 4, ebx);
}

static std::vector<unsigned char> QQMSG_encode_bytes(const std::vector<unsigned char> &plain, const unsigned char *key)
{
	int fill = (int)((8 - ((plain.size() + 10) % 8)) % 8);
	std::vector<unsigned char> in(fill + 10 + plain.size(), 0);
	std::vector<unsigned char> out(in.size(), 0);
	unsigned char prev_decrypt[8] = {0};
	unsigned char prev_crypt[8] = {0};
	unsigned char block[8], enc[8];
	size_t pos = 0;

	in[0] = (unsigned char)fill;
	for(size_t i = 0; i < plain.size(); i++)
		in[(size_t)fill + 3 + i] = plain[i];

	while(pos < in.size()) {
		unsigned char old_prev_crypt[8];
		memcpy(old_prev_crypt, prev_crypt, sizeof(old_prev_crypt));
		for(int i = 0; i < 8; i++)
			block[i] = in[pos + i] ^ prev_crypt[i];
		MsgEx_BlowfishEncryptBlock(block, key, enc);
		for(int i = 0; i < 8; i++) {
			out[pos + i] = enc[i] ^ prev_decrypt[i];
			prev_decrypt[i] = in[pos + i] ^ old_prev_crypt[i];
			prev_crypt[i] = out[pos + i];
		}
		pos += 8;
	}
	return out;
}

static std::string import_native_text(const std::string &s)
{
#ifdef _WIN32
	return s;
#else
	return MsgEx_Utf8ToGbk(s);
#endif
}

static bool parse_record_header(const std::string &line, time_t *when, std::string *name)
{
	int y, mo, d, h, mi, se;
	struct tm tmv;

	if(line.size() < 21 || line[4] != '-' || line[7] != '-' || line[10] != ' ' || line[13] != ':' || line[16] != ':' || line[19] != ' ')
		return false;
	if(sscanf(line.c_str(), "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &se) != 6)
		return false;
	memset(&tmv, 0, sizeof(tmv));
	tmv.tm_year = y - 1900;
	tmv.tm_mon = mo - 1;
	tmv.tm_mday = d;
	tmv.tm_hour = h;
	tmv.tm_min = mi;
	tmv.tm_sec = se;
	tmv.tm_isdst = -1;
	*when = mktime(&tmv);
	*name = line.substr(20);
	return *when != (time_t)-1;
}

static int import_msg_type_from_title(const std::string &title)
{
	if(title == "用户消息")
		return QQEX_MSGTYPE_C2CMSG;
	if(title == "聊天记录")
		return QQEX_MSGTYPE_C2CMSG;
	if(title == "系统消息")
		return QQEX_MSGTYPE_SYSMSG;
	if(title == "IMInfo")
		return QQEX_MSGTYPE_IMINFO;
	if(title == "DiscMsg")
		return QQEX_MSGTYPE_DISCMSG;
	if(title == "群组消息")
		return QQEX_MSGTYPE_GROUPMSG;
	if(title == "移动消息")
		return QQEX_MSGTYPE_MOBILEMSG;
	if(title == "临时会话")
		return QQEX_MSGTYPE_TEMPSESSIONMSG;
	return 0;
}

static bool import_line_value(const std::string &line, const char *key, std::string *value)
{
	size_t n = strlen(key);
	if(line.compare(0, n, key) == 0) {
		*value = line.substr(n);
		return true;
	}
	return false;
}

static std::string import_strip_legacy_name(const std::string &value)
{
	size_t pos = value.find('(');
	if(pos == std::string::npos)
		return value;
	return value.substr(0, pos);
}

static const char *import_msg_type_name(int type)
{
	switch(type) {
	case QQEX_MSGTYPE_C2CMSG: return "C2CMsg";
	case QQEX_MSGTYPE_SYSMSG: return "SysMsg";
	case QQEX_MSGTYPE_IMINFO: return "IMInfo";
	case QQEX_MSGTYPE_DISCMSG: return "DiscMsg";
	case QQEX_MSGTYPE_GROUPMSG: return "GroupMsg";
	case QQEX_MSGTYPE_MOBILEMSG: return "MobileMsg";
	case QQEX_MSGTYPE_TEMPSESSIONMSG: return "TempSessionMsg";
	default: return "C2CMsg";
	}
}

static void finish_import_record(std::vector<ImportSection> &sections, int current_section, bool *have, ImportRecord *rec)
{
	if(!*have)
		return;
	while(!rec->msg.empty() && rec->msg[rec->msg.size() - 1] == '\n')
		rec->msg.erase(rec->msg.size() - 1);
	if(current_section >= 0)
		sections[(size_t)current_section].records.push_back(*rec);
	*have = false;
}

static bool read_import_txt(const char *fname, std::vector<ImportSection> &sections, std::vector<int> &types, std::string *uid)
{
	FILE *fp = fopen(fname, "rb");
	char buf[8192];
	int current_type = 0;
	std::string current_object;
	int current_section = -1;
	bool current_object_auto = false;
	ImportRecord rec;
	bool have_record = false;

	if(!fp)
		return false;
	while(fgets(buf, sizeof(buf), fp)) {
		std::string line(buf);
		std::string value;
		time_t when;
		std::string name;

		while(!line.empty() && (line[line.size() - 1] == '\n' || line[line.size() - 1] == '\r'))
			line.erase(line.size() - 1);

		if(import_line_value(line, "用户：", &value)) {
			*uid = value;
			continue;
		}
		if(import_line_value(line, "用户:", &value)) {
			*uid = import_strip_legacy_name(value);
			continue;
		}
		if(import_line_value(line, "消息组:", &value)) {
			finish_import_record(sections, current_section, &have_record, &rec);
			current_object.clear();
			current_section = -1;
			current_object_auto = false;
			if(value == "系统消息") {
				current_type = QQEX_MSGTYPE_SYSMSG;
				if(types.empty() || types[types.size() - 1] != current_type)
					types.push_back(current_type);
			}else{
				current_type = 0;
			}
			continue;
		}
		if(import_line_value(line, "消息类型：", &value) || import_line_value(line, "消息类型:", &value)) {
			finish_import_record(sections, current_section, &have_record, &rec);
			current_type = import_msg_type_from_title(value);
			if(current_type != 0 && (types.empty() || types[types.size() - 1] != current_type))
				types.push_back(current_type);
			current_object.clear();
			current_section = -1;
			current_object_auto = false;
			continue;
		}
		if(import_line_value(line, "消息对象：", &value) || import_line_value(line, "消息对象:", &value)) {
			ImportSection section;
			finish_import_record(sections, current_section, &have_record, &rec);
			current_object = import_strip_legacy_name(value);
			section.msg_type = current_type;
			section.object = current_object;
			sections.push_back(section);
			current_section = (int)sections.size() - 1;
			current_object_auto = false;
			continue;
		}
		if(current_type != 0 && parse_record_header(line, &when, &name)) {
			if(current_section < 0 || (current_object_auto && current_type == QQEX_MSGTYPE_SYSMSG && current_object != name)) {
				ImportSection section;
				finish_import_record(sections, current_section, &have_record, &rec);
				current_object = name;
				section.msg_type = current_type;
				section.object = current_object;
				sections.push_back(section);
				current_section = (int)sections.size() - 1;
				current_object_auto = true;
			}
			finish_import_record(sections, current_section, &have_record, &rec);
			rec.msg_type = current_type;
			rec.object = current_object;
			rec.when = when;
			rec.name = name;
			rec.msg.clear();
			have_record = true;
			continue;
		}
		if(have_record) {
			rec.msg += line;
			rec.msg += '\n';
		}
	}
	finish_import_record(sections, current_section, &have_record, &rec);
	fclose(fp);
	return true;
}

static std::vector<unsigned char> build_plain_record(const ImportRecord &rec)
{
	std::string name = import_native_text(rec.name);
	std::string msg = import_native_text(rec.msg);
	std::vector<unsigned char> out;

	put_le32(out, (uint32_t)rec.when);
	switch(rec.msg_type) {
	case QQEX_MSGTYPE_SYSMSG:
	case QQEX_MSGTYPE_TEMPSESSIONMSG:
		put_le32(out, 0);
		break;
	case QQEX_MSGTYPE_GROUPMSG:
		put_le32(out, 0);
		put_le32(out, 0);
		break;
	case QQEX_MSGTYPE_DISCMSG:
		out.push_back(1);
		put_le32(out, 0);
		put_le32(out, 0);
		put_le32(out, 0);
		break;
	default:
		out.push_back(0);
		break;
	}
	put_le32(out, (uint32_t)name.size());
	out.insert(out.end(), name.begin(), name.end());
	put_le32(out, (uint32_t)msg.size() + 1);
	out.insert(out.end(), msg.begin(), msg.end());
	out.push_back(0);
	return out;
}

static std::vector<unsigned char> build_index_stream(const std::vector<std::vector<unsigned char> > &encoded_records)
{
	std::vector<unsigned char> out;
	uint32_t offset = 0;
	for(size_t i = 0; i < encoded_records.size(); i++) {
		put_le32(out, offset);
		offset += (uint32_t)encoded_records[i].size();
	}
	return out;
}

static std::vector<unsigned char> build_data_stream(const std::vector<std::vector<unsigned char> > &encoded_records)
{
	std::vector<unsigned char> out;
	for(size_t i = 0; i < encoded_records.size(); i++)
		out.insert(out.end(), encoded_records[i].begin(), encoded_records[i].end());
	return out;
}

static void matrix_obfuscate_record(std::vector<unsigned char> &matrix, size_t name_pos, size_t name_len, size_t data_pos, size_t data_len, uint8_t rtype)
{
	unsigned char e = (unsigned char)(((name_len >> 8) & 0xff) ^ (name_len & 0xff));
	for(size_t i = 0; i < name_len; i++)
		matrix[name_pos + i] = (unsigned char)(~matrix[name_pos + i] ^ e);
	if(rtype == 6 || rtype == 7) {
		e = (unsigned char)(((data_len >> 8) & 0xff) ^ (data_len & 0xff));
		for(size_t i = 0; i < data_len; i++)
			matrix[data_pos + i] = (unsigned char)(~matrix[data_pos + i] ^ e);
	}
}

static void matrix_append_record(std::vector<unsigned char> &matrix, uint8_t rtype, const char *name, const std::vector<unsigned char> &data)
{
	size_t name_len = strlen(name);
	size_t name_pos, data_pos;

	matrix.push_back(rtype);
	put_le16(matrix, (uint16_t)name_len);
	name_pos = matrix.size();
	matrix.insert(matrix.end(), name, name + name_len);
	put_le32(matrix, (uint32_t)data.size());
	data_pos = matrix.size();
	matrix.insert(matrix.end(), data.begin(), data.end());
	matrix_obfuscate_record(matrix, name_pos, name_len, data_pos, data.size(), rtype);
}

static std::vector<unsigned char> build_matrix_db(const char *uid, const unsigned char *msg_key)
{
	unsigned char uid_md5[16];
	std::vector<unsigned char> key_plain(msg_key, msg_key + 16);
	std::vector<unsigned char> crk;
	std::vector<unsigned char> matrix;
	std::vector<unsigned char> zeros32(32, 0);
	std::vector<unsigned char> zeros416(416, 0);
	std::vector<unsigned char> stl(1, 0);
	std::vector<unsigned char> tip(4, 0);
	static const char des[] = "Stop your hacking,Matrix everywhere,the truth is out here. nanoJedi20020325am0939. For the horde! Mal050711";

	MD5((char*)uid, strlen(uid), (char*)uid_md5);
	crk = QQMSG_encode_bytes(key_plain, uid_md5);
	matrix.push_back('Q');
	matrix.push_back('D');
	matrix.push_back(1);
	matrix.push_back(1);
	matrix.push_back(8);
	matrix.push_back(0);
	matrix_append_record(matrix, 2, "STL", stl);
	matrix_append_record(matrix, 1, "TIP", tip);
	matrix_append_record(matrix, 7, "CRK", crk);
	matrix_append_record(matrix, 7, "CAH", zeros32);
	matrix_append_record(matrix, 7, "CPH", zeros32);
	matrix_append_record(matrix, 7, "CLT", zeros416);
	matrix_append_record(matrix, 6, "DES", std::vector<unsigned char>(des, des + strlen(des)));
	matrix_append_record(matrix, 6, "QUE", std::vector<unsigned char>());
	return matrix;
}

static int add_cfb_entry(std::vector<ImportStream> &entries, const std::string &name, uint8_t type, const std::vector<unsigned char> &data)
{
	ImportStream e;
	e.name = name;
	e.type = type;
	e.color = 1;
	e.left = -1;
	e.child = -1;
	e.right = -1;
	e.data = data;
	e.start = (uint32_t)CFB_ENDOFCHAIN;
	e.size = data.size();
	entries.push_back(e);
	return (int)entries.size() - 1;
}

static void link_child(std::vector<ImportStream> &entries, int parent, int child)
{
	entries[child].left = -1;
	entries[child].right = -1;
	if(entries[parent].child < 0) {
		entries[parent].child = child;
		return;
	}
	int last = entries[parent].child;
	while(entries[last].right >= 0)
		last = entries[last].right;
	entries[last].right = child;
}

static bool cfb_dir_less(const std::vector<ImportStream> &entries, int a, int b)
{
	const std::string &an = entries[(size_t)a].name;
	const std::string &bn = entries[(size_t)b].name;
	if(an.size() != bn.size())
		return an.size() < bn.size();
	for(size_t i = 0; i < an.size(); i++) {
		unsigned char ac = (unsigned char)toupper((unsigned char)an[i]);
		unsigned char bc = (unsigned char)toupper((unsigned char)bn[i]);
		if(ac != bc)
			return ac < bc;
	}
	return a < b;
}

static bool cfb_dir_is_red(const std::vector<ImportStream> &entries, int node)
{
	return node >= 0 && (size_t)node < entries.size() && entries[(size_t)node].color == 0;
}

static int cfb_dir_rotate_left(std::vector<ImportStream> &entries, int h)
{
	int x = entries[(size_t)h].right;
	entries[(size_t)h].right = entries[(size_t)x].left;
	entries[(size_t)x].left = h;
	entries[(size_t)x].color = entries[(size_t)h].color;
	entries[(size_t)h].color = 0;
	return x;
}

static int cfb_dir_rotate_right(std::vector<ImportStream> &entries, int h)
{
	int x = entries[(size_t)h].left;
	entries[(size_t)h].left = entries[(size_t)x].right;
	entries[(size_t)x].right = h;
	entries[(size_t)x].color = entries[(size_t)h].color;
	entries[(size_t)h].color = 0;
	return x;
}

static void cfb_dir_flip_colors(std::vector<ImportStream> &entries, int h)
{
	int left = entries[(size_t)h].left;
	int right = entries[(size_t)h].right;
	entries[(size_t)h].color = entries[(size_t)h].color == 0 ? 1 : 0;
	if(left >= 0)
		entries[(size_t)left].color = entries[(size_t)left].color == 0 ? 1 : 0;
	if(right >= 0)
		entries[(size_t)right].color = entries[(size_t)right].color == 0 ? 1 : 0;
}

static int cfb_dir_insert_rb(std::vector<ImportStream> &entries, int h, int node)
{
	if(h < 0) {
		entries[(size_t)node].left = -1;
		entries[(size_t)node].right = -1;
		entries[(size_t)node].color = 0;
		return node;
	}

	if(cfb_dir_less(entries, node, h))
		entries[(size_t)h].left = cfb_dir_insert_rb(entries, entries[(size_t)h].left, node);
	else
		entries[(size_t)h].right = cfb_dir_insert_rb(entries, entries[(size_t)h].right, node);

	if(cfb_dir_is_red(entries, entries[(size_t)h].right) && !cfb_dir_is_red(entries, entries[(size_t)h].left))
		h = cfb_dir_rotate_left(entries, h);
	if(cfb_dir_is_red(entries, entries[(size_t)h].left) && cfb_dir_is_red(entries, entries[(size_t)entries[(size_t)h].left].left))
		h = cfb_dir_rotate_right(entries, h);
	if(cfb_dir_is_red(entries, entries[(size_t)h].left) && cfb_dir_is_red(entries, entries[(size_t)h].right))
		cfb_dir_flip_colors(entries, h);
	return h;
}

static void collect_cfb_sibling_tree(const std::vector<ImportStream> &entries, int child, std::vector<int> &children)
{
	if(child < 0 || (size_t)child >= entries.size())
		return;
	collect_cfb_sibling_tree(entries, entries[(size_t)child].left, children);
	children.push_back(child);
	collect_cfb_sibling_tree(entries, entries[(size_t)child].right, children);
}

static void finalize_cfb_directory_tree(std::vector<ImportStream> &entries, int parent)
{
	std::vector<int> children;
	int child = entries[parent].child;

	collect_cfb_sibling_tree(entries, child, children);
	for(size_t i = 0; i < children.size(); i++)
		finalize_cfb_directory_tree(entries, children[i]);
	std::sort(children.begin(), children.end(), [&](int a, int b) {
		return cfb_dir_less(entries, a, b);
	});
	int root = -1;
	for(size_t i = 0; i < children.size(); i++) {
		entries[children[i]].left = -1;
		entries[children[i]].right = -1;
		entries[children[i]].color = 1;
		root = cfb_dir_insert_rb(entries, root, children[i]);
	}
	if(root >= 0)
		entries[(size_t)root].color = 1;
	entries[parent].child = root;
}

static void write_dir_entry(unsigned char *p, const ImportStream &e)
{
	size_t chars = e.name.size();
	if(chars > 31)
		chars = 31;
	memset(p, 0, 128);
	if(e.type == 0)
		return;
	for(size_t i = 0; i < chars; i++) {
		p[i * 2] = (unsigned char)e.name[i];
		p[i * 2 + 1] = 0;
	}
	set_le16(p + 64, (uint16_t)((chars + 1) * 2));
	p[66] = e.type;
	p[67] = e.color;
	set_le32(p + 68, e.left >= 0 ? (uint32_t)e.left : 0xffffffffu);
	set_le32(p + 72, e.right >= 0 ? (uint32_t)e.right : 0xffffffffu);
	set_le32(p + 76, e.child >= 0 ? (uint32_t)e.child : 0xffffffffu);
	set_le32(p + 116, e.start);
	set_le64(p + 120, e.size);
}

static bool write_cfb_file_ex(const char *fname, std::vector<ImportStream> &entries, bool sort_directory)
{
	const uint32_t sector_size = 512;
	const uint32_t mini_sector_size = 64;
	const uint32_t mini_cutoff = 4096;
	const size_t fat_entries_per_sector = sector_size / 4;
	const size_t mini_fat_entries_per_sector = sector_size / 4;
	std::vector<uint32_t> stream_sectors(entries.size(), 0);
	std::vector<uint32_t> mini_stream_starts(entries.size(), (uint32_t)CFB_ENDOFCHAIN);
	std::vector<unsigned char> mini_stream;
	std::vector<int32_t> mini_fat;
	uint32_t dir_sectors;
	uint32_t mini_fat_sectors;
	uint32_t mini_stream_sectors;
	uint32_t difat_sectors = 0, old_difat_sectors = 0;
	uint32_t fat_sectors = 1, old_fat_sectors = 0;
	uint32_t nonfat_sectors = 0, total_sectors;
	std::vector<int32_t> fat;
	std::vector<unsigned char> header(512, 0);
	FILE *fp;

	if(sort_directory && !entries.empty())
		finalize_cfb_directory_tree(entries, 0);

	dir_sectors = (uint32_t)(((entries.size() * 128) + sector_size - 1) / sector_size);
	if(dir_sectors == 0)
		dir_sectors = 1;
	for(size_t i = 0; i < entries.size(); i++) {
		if(entries[i].type == STGTY_STREAM && entries[i].size > 0 && entries[i].size < mini_cutoff) {
			uint32_t start = (uint32_t)mini_fat.size();
			uint32_t mini_count = (uint32_t)((entries[i].size + mini_sector_size - 1) / mini_sector_size);
			mini_stream_starts[i] = start;
			for(uint32_t j = 0; j < mini_count; j++)
				mini_fat.push_back((j + 1 < mini_count) ? (int32_t)(start + j + 1) : CFB_ENDOFCHAIN);
			size_t old_size = mini_stream.size();
			mini_stream.resize(old_size + (size_t)mini_count * mini_sector_size, 0);
			memcpy(&mini_stream[old_size], &entries[i].data[0], entries[i].data.size());
			entries[i].start = start;
		}else if(entries[i].type == STGTY_STREAM && entries[i].size > 0) {
			stream_sectors[i] = (uint32_t)((entries[i].size + sector_size - 1) / sector_size);
			nonfat_sectors += stream_sectors[i];
		}
	}
	mini_fat_sectors = mini_fat.empty() ? 0 : (uint32_t)((mini_fat.size() + mini_fat_entries_per_sector - 1) / mini_fat_entries_per_sector);
	mini_stream_sectors = mini_stream.empty() ? 0 : (uint32_t)((mini_stream.size() + sector_size - 1) / sector_size);
	if(!mini_stream.empty()) {
		entries[0].size = mini_stream.size();
		nonfat_sectors += mini_stream_sectors;
	}
	nonfat_sectors += mini_fat_sectors;
	nonfat_sectors += dir_sectors;
	while(fat_sectors != old_fat_sectors || difat_sectors != old_difat_sectors) {
		old_fat_sectors = fat_sectors;
		old_difat_sectors = difat_sectors;
		difat_sectors = fat_sectors > 109 ? (uint32_t)((fat_sectors - 109 + 126) / 127) : 0;
		fat_sectors = (uint32_t)((nonfat_sectors + fat_sectors + difat_sectors + fat_entries_per_sector - 1) / fat_entries_per_sector);
	}
	difat_sectors = fat_sectors > 109 ? (uint32_t)((fat_sectors - 109 + 126) / 127) : 0;
	total_sectors = nonfat_sectors + fat_sectors + difat_sectors;
	fat.assign(total_sectors, CFB_FREESECT);
	for(uint32_t i = 0; i < fat_sectors; i++)
		fat[i] = CFB_FATSECT;
	for(uint32_t i = 0; i < difat_sectors; i++)
		fat[fat_sectors + i] = CFB_DIFSECT;

	uint32_t next = fat_sectors + difat_sectors;
	uint32_t first_mini_fat_sector = mini_fat_sectors ? next : (uint32_t)CFB_ENDOFCHAIN;
	for(uint32_t i = 0; i < mini_fat_sectors; i++)
		fat[next + i] = (i + 1 < mini_fat_sectors) ? (int32_t)(next + i + 1) : CFB_ENDOFCHAIN;
	next += mini_fat_sectors;

	uint32_t first_dir_sector = next;
	for(uint32_t i = 0; i < dir_sectors; i++)
		fat[next + i] = (i + 1 < dir_sectors) ? (int32_t)(next + i + 1) : CFB_ENDOFCHAIN;
	next += dir_sectors;

	for(size_t i = 0; i < entries.size(); i++) {
		if(stream_sectors[i] == 0)
			continue;
		entries[i].start = next;
		for(uint32_t j = 0; j < stream_sectors[i]; j++)
			fat[next + j] = (j + 1 < stream_sectors[i]) ? (int32_t)(next + j + 1) : CFB_ENDOFCHAIN;
		next += stream_sectors[i];
	}
	if(mini_stream_sectors > 0) {
		entries[0].start = next;
		for(uint32_t j = 0; j < mini_stream_sectors; j++)
			fat[next + j] = (j + 1 < mini_stream_sectors) ? (int32_t)(next + j + 1) : CFB_ENDOFCHAIN;
		next += mini_stream_sectors;
	}

	static const unsigned char magic[8] = {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1};
	memcpy(&header[0], magic, sizeof(magic));
	set_le16(&header[24], 0x003e);
	set_le16(&header[26], 0x0003);
	set_le16(&header[28], 0xfffe);
	set_le16(&header[30], 9);
	set_le16(&header[32], 6);
	set_le32(&header[44], fat_sectors);
	set_le32(&header[48], first_dir_sector);
	set_le32(&header[56], mini_cutoff);
	set_le32(&header[60], first_mini_fat_sector);
	set_le32(&header[64], mini_fat_sectors);
	set_le32(&header[68], difat_sectors ? fat_sectors : 0xffffffffu);
	set_le32(&header[72], difat_sectors);
	for(int i = 0; i < 109; i++)
		set_le32(&header[76 + i * 4], i < (int)fat_sectors ? (uint32_t)i : 0xffffffffu);

	fp = fopen(fname, "wb");
	if(!fp)
		return false;
	fwrite(&header[0], 1, header.size(), fp);
	for(uint32_t fs = 0; fs < fat_sectors; fs++) {
		std::vector<unsigned char> sec(sector_size, 0xff);
		for(size_t i = 0; i < fat_entries_per_sector; i++) {
			size_t idx = (size_t)fs * fat_entries_per_sector + i;
			if(idx < fat.size())
				set_le32(&sec[i * 4], (uint32_t)fat[idx]);
		}
		fwrite(&sec[0], 1, sec.size(), fp);
	}
	for(uint32_t ds = 0; ds < difat_sectors; ds++) {
		std::vector<unsigned char> sec(sector_size, 0xff);
		for(size_t i = 0; i < 127; i++) {
			uint32_t fat_id = 109 + ds * 127 + (uint32_t)i;
			if(fat_id < fat_sectors)
				set_le32(&sec[i * 4], fat_id);
		}
		set_le32(&sec[127 * 4], (ds + 1 < difat_sectors) ? (fat_sectors + ds + 1) : 0xffffffffu);
		fwrite(&sec[0], 1, sec.size(), fp);
	}
	for(uint32_t fs = 0; fs < mini_fat_sectors; fs++) {
		std::vector<unsigned char> sec(sector_size, 0xff);
		for(size_t i = 0; i < mini_fat_entries_per_sector; i++) {
			size_t idx = (size_t)fs * mini_fat_entries_per_sector + i;
			if(idx < mini_fat.size())
				set_le32(&sec[i * 4], (uint32_t)mini_fat[idx]);
		}
		fwrite(&sec[0], 1, sec.size(), fp);
	}
	{
		std::vector<unsigned char> dir(dir_sectors * sector_size, 0);
		for(size_t i = 0; i < entries.size(); i++)
			write_dir_entry(&dir[i * 128], entries[i]);
		fwrite(&dir[0], 1, dir.size(), fp);
	}
	for(size_t i = 0; i < entries.size(); i++) {
		if(stream_sectors[i] == 0)
			continue;
		std::vector<unsigned char> data(stream_sectors[i] * sector_size, 0);
		memcpy(&data[0], &entries[i].data[0], entries[i].data.size());
		fwrite(&data[0], 1, data.size(), fp);
	}
	if(mini_stream_sectors > 0) {
		std::vector<unsigned char> data(mini_stream_sectors * sector_size, 0);
		memcpy(&data[0], &mini_stream[0], mini_stream.size());
		fwrite(&data[0], 1, data.size(), fp);
	}
	fclose(fp);
	return true;
}

static bool write_cfb_file(const char *fname, std::vector<ImportStream> &entries)
{
	return write_cfb_file_ex(fname, entries, true);
}

#ifndef _WIN32
static bool load_template_entries_preserve_order(const CfbFile &cfb, std::vector<ImportStream> &entries)
{
	entries.clear();
	for(size_t i = 0; i < cfb.dirs.size(); i++) {
		const CfbDirEntry &dir = cfb.dirs[i];
		ImportStream e;
		e.name = dir.name;
		e.type = dir.type;
		e.color = dir.color;
		e.left = dir.left;
		e.child = dir.child;
		e.right = dir.right;
		e.start = dir.start;
		e.size = dir.size;
		if(dir.type == STGTY_STREAM && dir.size > 0) {
			if(!cfb_stream_data(cfb, dir, e.data))
				return false;
			e.size = e.data.size();
		}
		entries.push_back(e);
	}
	return !entries.empty();
}

static int add_template_entries_from_cfb(const CfbFile &cfb, int32_t sid, int parent, std::vector<ImportStream> &entries)
{
	if(sid < 0 || (size_t)sid >= cfb.dirs.size())
		return -1;

	const CfbDirEntry &dir = cfb.dirs[(size_t)sid];
	add_template_entries_from_cfb(cfb, dir.left, parent, entries);

	if(dir.type == STGTY_STORAGE || dir.type == STGTY_STREAM) {
		std::vector<unsigned char> data;
		if(dir.type == STGTY_STREAM && dir.size > 0)
			cfb_stream_data(cfb, dir, data);
		int id = add_cfb_entry(entries, dir.name, dir.type, data);
		link_child(entries, parent, id);
		if(dir.type == STGTY_STORAGE)
			add_template_entries_from_cfb(cfb, dir.child, id, entries);
	}

	add_template_entries_from_cfb(cfb, dir.right, parent, entries);
	return 0;
}

static int find_import_child(const std::vector<ImportStream> &entries, int parent, const std::string &name, int type)
{
	std::vector<int> stack;

	if(parent < 0 || (size_t)parent >= entries.size())
		return -1;
	if(entries[(size_t)parent].child >= 0)
		stack.push_back(entries[(size_t)parent].child);
	while(!stack.empty()) {
		int child = stack.back();
		stack.pop_back();
		if(child < 0 || (size_t)child >= entries.size())
			continue;
		if(entries[(size_t)child].name == name && (type == 0 || entries[(size_t)child].type == type))
			return child;
		if(entries[(size_t)child].left >= 0)
			stack.push_back(entries[(size_t)child].left);
		if(entries[(size_t)child].right >= 0)
			stack.push_back(entries[(size_t)child].right);
	}
	return -1;
}

static bool template_msg_key(std::vector<ImportStream> &entries, const char *uid, unsigned char *msg_key)
{
	int matrix_stg = find_import_child(entries, 0, "Matrix", STGTY_STORAGE);
	int matrix_db;
	std::vector<unsigned char> matrix;
	char uid_md5[16];
	char *pCRK;
	int pCRKLen = 0;
	int pLen = 16;

	if(matrix_stg < 0)
		matrix_db = find_import_child(entries, 0, "Matrix.db", STGTY_STREAM);
	else
		matrix_db = find_import_child(entries, matrix_stg, "Matrix.db", STGTY_STREAM);
	if(matrix_db < 0)
		return false;

	matrix = entries[(size_t)matrix_db].data;
	if(matrix.empty())
		return false;
	MsgEx_DecodeMatrixDB((char*)&matrix[0], (int)matrix.size());
	pCRK = MsgEx_FindMatrixDB((char*)&matrix[0], (int)matrix.size(), (char*)"CRK", &pCRKLen);
	if(!pCRK || pCRKLen <= 0)
		return false;

	MD5((char*)uid, strlen(uid), uid_md5);
	if(QQMSG_decode(pCRK, pCRKLen, uid_md5, (char*)msg_key, &pLen) < 0 || pLen != 16)
		return false;
	return true;
}

static uint32_t cfb_sector_count_for_size(size_t size)
{
	return (uint32_t)((size + 511) / 512);
}

static uint32_t cfb_mini_count_for_size(size_t size)
{
	return (uint32_t)((size + 63) / 64);
}

static void cfb_set_header_difat(std::vector<unsigned char> &out, const std::vector<int32_t> &fat, const std::vector<uint32_t> &fat_sector_ids, const std::vector<uint32_t> &difat_sector_ids)
{
	for(int i = 0; i < 109; i++)
		set_le32(&out[76 + i * 4], i < (int)fat_sector_ids.size() ? fat_sector_ids[(size_t)i] : 0xffffffffu);

	set_le32(&out[68], difat_sector_ids.empty() ? 0xffffffffu : difat_sector_ids[0]);
	set_le32(&out[72], (uint32_t)difat_sector_ids.size());

	for(size_t d = 0; d < difat_sector_ids.size(); d++) {
		size_t off = ((size_t)difat_sector_ids[d] + 1) * 512;
		std::vector<unsigned char> sec(512, 0xff);
		for(size_t i = 0; i < 127; i++) {
			size_t idx = 109 + d * 127 + i;
			if(idx < fat_sector_ids.size())
				set_le32(&sec[i * 4], fat_sector_ids[idx]);
		}
		set_le32(&sec[127 * 4], (d + 1 < difat_sector_ids.size()) ? difat_sector_ids[d + 1] : 0xffffffffu);
		memcpy(&out[off], &sec[0], sec.size());
	}
}

static bool write_cfb_template_patch(const char *outdb, const CfbFile &cfb, std::vector<ImportStream> &entries)
{
	const uint32_t sector_size = 512;
	const uint32_t mini_cutoff = 4096;
	uint32_t original_sector_count = (uint32_t)(cfb.bytes.size() / sector_size - 1);
	uint32_t old_fat_sectors = cfb.num_fat_sectors;
	uint32_t old_difat_sectors = cfb.num_difat_sectors;
	uint32_t additional_regular = 0;
	uint32_t additional_mini = 0;
	uint32_t dir_sectors = cfb_sector_count_for_size(entries.size() * 128);
	bool rewrite_dir = entries.size() != cfb.dirs.size();
	std::vector<unsigned char> mini_stream = cfb.mini_stream;
	std::vector<int32_t> mini_fat = cfb.mini_fat;
	std::vector<int32_t> fat = cfb.fat;
	std::vector<uint32_t> stream_regular_sectors(entries.size(), 0);
	std::vector<uint32_t> stream_mini_sectors(entries.size(), 0);

	if(fat.size() < original_sector_count)
		fat.resize(original_sector_count, CFB_FREESECT);
	for(size_t i = 0; i < entries.size() && i < cfb.dirs.size(); i++) {
		if(entries[i].left != cfb.dirs[i].left || entries[i].right != cfb.dirs[i].right || entries[i].child != cfb.dirs[i].child) {
			rewrite_dir = true;
			break;
		}
	}

	for(size_t i = 0; i < entries.size(); i++) {
		if(entries[i].type != STGTY_STREAM || entries[i].data.empty())
			continue;
		bool changed = false;
		if(i >= cfb.dirs.size() || entries[i].size != cfb.dirs[i].size)
			changed = true;
		else if(entries[i].data.size() != cfb.dirs[i].size)
			changed = true;
		if(!changed)
			continue;
		if(entries[i].data.size() < mini_cutoff) {
			stream_mini_sectors[i] = cfb_mini_count_for_size(entries[i].data.size());
			additional_mini += stream_mini_sectors[i];
		}else{
			stream_regular_sectors[i] = cfb_sector_count_for_size(entries[i].data.size());
			additional_regular += stream_regular_sectors[i];
		}
	}

	bool touches_mini = additional_mini > 0;
	uint32_t mini_fat_entries = touches_mini ? (uint32_t)mini_fat.size() + additional_mini : 0;
	uint32_t mini_fat_sectors = mini_fat_entries ? (uint32_t)((mini_fat_entries * 4 + sector_size - 1) / sector_size) : 0;
	if(mini_stream.size() < mini_fat.size() * 64)
		mini_stream.resize(mini_fat.size() * 64, 0);
	uint32_t root_mini_size = touches_mini ? (uint32_t)mini_stream.size() + additional_mini * 64 : 0;
	uint32_t root_mini_sectors = root_mini_size ? cfb_sector_count_for_size(root_mini_size) : 0;
	uint32_t new_dir_sectors = rewrite_dir ? dir_sectors : 0;
	uint32_t base_new = additional_regular + new_dir_sectors + mini_fat_sectors + root_mini_sectors;
	uint32_t final_fat_sectors = old_fat_sectors;
	uint32_t final_difat_sectors = old_difat_sectors;
	uint32_t old_final_fat = 0, old_final_difat = 0;

	while(final_fat_sectors != old_final_fat || final_difat_sectors != old_final_difat) {
		old_final_fat = final_fat_sectors;
		old_final_difat = final_difat_sectors;
		uint32_t fat_id_slots = final_fat_sectors > 109 ? final_fat_sectors - 109 : 0;
		final_difat_sectors = fat_id_slots ? (uint32_t)((fat_id_slots + 126) / 127) : 0;
		if(final_difat_sectors < old_difat_sectors)
			final_difat_sectors = old_difat_sectors;
		uint32_t total = original_sector_count + base_new + (final_fat_sectors - old_fat_sectors) + (final_difat_sectors - old_difat_sectors);
		final_fat_sectors = (uint32_t)((total + 127) / 128);
		if(final_fat_sectors < old_fat_sectors)
			final_fat_sectors = old_fat_sectors;
	}

	uint32_t new_fat_sectors = final_fat_sectors - old_fat_sectors;
	uint32_t new_difat_sectors = final_difat_sectors - old_difat_sectors;
	uint32_t final_sector_count = original_sector_count + base_new + new_fat_sectors + new_difat_sectors;

	std::vector<unsigned char> out = cfb.bytes;
	out.resize(((size_t)final_sector_count + 1) * sector_size, 0);
	fat.resize(final_sector_count, CFB_FREESECT);

	std::vector<uint32_t> new_regular_ids;
	std::vector<uint32_t> dir_ids;
	std::vector<uint32_t> mini_fat_ids;
	std::vector<uint32_t> root_mini_ids;
	std::vector<uint32_t> new_fat_ids;
	std::vector<uint32_t> new_difat_ids;
	uint32_t next_sector = original_sector_count;
	auto take_sector = [&]() { return next_sector++; };

	for(uint32_t i = 0; i < additional_regular; i++) new_regular_ids.push_back(take_sector());
	if(rewrite_dir) {
		for(uint32_t i = 0; i < dir_sectors; i++) dir_ids.push_back(take_sector());
	}else{
		int32_t sid = cfb.first_dir_sector;
		while(sid >= 0 && sid != CFB_ENDOFCHAIN && (size_t)sid < cfb.fat.size()) {
			dir_ids.push_back((uint32_t)sid);
			sid = cfb.fat[(size_t)sid];
		}
	}
	for(uint32_t i = 0; i < mini_fat_sectors; i++) mini_fat_ids.push_back(take_sector());
	for(uint32_t i = 0; i < root_mini_sectors; i++) root_mini_ids.push_back(take_sector());
	for(uint32_t i = 0; i < new_fat_sectors; i++) new_fat_ids.push_back(take_sector());
	for(uint32_t i = 0; i < new_difat_sectors; i++) new_difat_ids.push_back(take_sector());

	auto write_sector = [&](uint32_t sid, const unsigned char *data, size_t len) {
		size_t off = ((size_t)sid + 1) * sector_size;
		memset(&out[off], 0, sector_size);
		if(data && len > 0)
			memcpy(&out[off], data, len > sector_size ? sector_size : len);
	};
	auto set_chain = [&](const std::vector<uint32_t> &ids) {
		for(size_t i = 0; i < ids.size(); i++)
			fat[ids[i]] = (i + 1 < ids.size()) ? (int32_t)ids[i + 1] : CFB_ENDOFCHAIN;
	};

	size_t regular_pos = 0;
	for(size_t i = 0; i < entries.size(); i++) {
		if(stream_regular_sectors[i] == 0)
			continue;
		std::vector<uint32_t> ids;
		for(uint32_t j = 0; j < stream_regular_sectors[i]; j++)
			ids.push_back(new_regular_ids[regular_pos++]);
		for(size_t j = 0; j < ids.size(); j++) {
			size_t data_off = j * sector_size;
			size_t remain = entries[i].data.size() > data_off ? entries[i].data.size() - data_off : 0;
			write_sector(ids[j], remain ? &entries[i].data[data_off] : NULL, remain);
		}
		set_chain(ids);
		entries[i].start = ids.empty() ? (uint32_t)CFB_ENDOFCHAIN : ids[0];
		entries[i].size = entries[i].data.size();
	}

	for(size_t i = 0; i < entries.size(); i++) {
		if(stream_mini_sectors[i] == 0)
			continue;
		uint32_t start = (uint32_t)mini_fat.size();
		entries[i].start = start;
		entries[i].size = entries[i].data.size();
		for(uint32_t j = 0; j < stream_mini_sectors[i]; j++)
			mini_fat.push_back((j + 1 < stream_mini_sectors[i]) ? (int32_t)(start + j + 1) : CFB_ENDOFCHAIN);
		size_t old_size = mini_stream.size();
		mini_stream.resize(old_size + (size_t)stream_mini_sectors[i] * 64, 0);
		memcpy(&mini_stream[old_size], &entries[i].data[0], entries[i].data.size());
	}

	if(touches_mini) {
		entries[0].start = root_mini_ids.empty() ? (uint32_t)CFB_ENDOFCHAIN : root_mini_ids[0];
		entries[0].size = mini_stream.size();
	}
	std::vector<unsigned char> dir_data;
	if(!cfb_read_regular_chain(cfb, cfb.first_dir_sector, UINT64_MAX, dir_data))
		return false;
	dir_data.resize(dir_sectors * sector_size, 0);
	for(size_t i = 0; i < entries.size(); i++) {
		size_t off = i * 128;
		if(off + 128 > dir_data.size())
			return false;
		if(i >= cfb.dirs.size())
			write_dir_entry(&dir_data[off], entries[i]);
		else {
			set_le32(&dir_data[off + 68], entries[i].left >= 0 ? (uint32_t)entries[i].left : 0xffffffffu);
			set_le32(&dir_data[off + 72], entries[i].right >= 0 ? (uint32_t)entries[i].right : 0xffffffffu);
			set_le32(&dir_data[off + 76], entries[i].child >= 0 ? (uint32_t)entries[i].child : 0xffffffffu);
			set_le32(&dir_data[off + 116], entries[i].start);
			set_le64(&dir_data[off + 120], entries[i].size);
		}
	}
	for(size_t i = 0; i < dir_ids.size(); i++) {
		size_t off = i * sector_size;
		write_sector(dir_ids[i], &dir_data[off], sector_size);
	}
	if(rewrite_dir)
		set_chain(dir_ids);

	if(touches_mini) {
		std::vector<unsigned char> mini_fat_data(mini_fat_sectors * sector_size, 0xff);
		for(size_t i = 0; i < mini_fat.size(); i++)
			set_le32(&mini_fat_data[i * 4], (uint32_t)mini_fat[i]);
		for(size_t i = 0; i < mini_fat_ids.size(); i++) {
			size_t off = i * sector_size;
			write_sector(mini_fat_ids[i], &mini_fat_data[off], sector_size);
		}
		set_chain(mini_fat_ids);
	}

	if(touches_mini) {
		for(size_t i = 0; i < root_mini_ids.size(); i++) {
			size_t off = i * sector_size;
			size_t remain = mini_stream.size() > off ? mini_stream.size() - off : 0;
			write_sector(root_mini_ids[i], remain ? &mini_stream[off] : NULL, remain);
		}
		set_chain(root_mini_ids);
	}

	for(size_t i = 0; i < new_fat_ids.size(); i++)
		fat[new_fat_ids[i]] = CFB_FATSECT;
	for(size_t i = 0; i < new_difat_ids.size(); i++)
		fat[new_difat_ids[i]] = CFB_DIFSECT;

	std::vector<uint32_t> fat_sector_ids;
	for(uint32_t i = 0; i < old_fat_sectors; i++) {
		uint32_t sid = cfb_le32(&cfb.bytes[76 + i * 4]);
		if(i < 109)
			sid = cfb_le32(&cfb.bytes[76 + i * 4]);
		fat_sector_ids.push_back(0);
	}
	fat_sector_ids.clear();
	for(int i = 0; i < 109 && fat_sector_ids.size() < old_fat_sectors; i++) {
		uint32_t sid = cfb_le32(&cfb.bytes[76 + i * 4]);
		if(sid != 0xffffffffu)
			fat_sector_ids.push_back(sid);
	}
	uint32_t dif_sid = cfb.first_difat_sector;
	for(uint32_t d = 0; d < cfb.num_difat_sectors && dif_sid != 0xffffffffu; d++) {
		size_t off = ((size_t)dif_sid + 1) * sector_size;
		for(size_t i = 0; i < 127 && fat_sector_ids.size() < old_fat_sectors; i++) {
			uint32_t sid = cfb_le32(&cfb.bytes[off + i * 4]);
			if(sid != 0xffffffffu)
				fat_sector_ids.push_back(sid);
		}
		dif_sid = cfb_le32(&cfb.bytes[off + 127 * 4]);
	}
	for(size_t i = 0; i < new_fat_ids.size(); i++)
		fat_sector_ids.push_back(new_fat_ids[i]);

	std::vector<uint32_t> difat_sector_ids;
	dif_sid = cfb.first_difat_sector;
	for(uint32_t d = 0; d < cfb.num_difat_sectors && dif_sid != 0xffffffffu; d++) {
		difat_sector_ids.push_back(dif_sid);
		size_t off = ((size_t)dif_sid + 1) * sector_size;
		dif_sid = cfb_le32(&cfb.bytes[off + 127 * 4]);
	}
	for(size_t i = 0; i < new_difat_ids.size(); i++)
		difat_sector_ids.push_back(new_difat_ids[i]);

	for(size_t fs = 0; fs < fat_sector_ids.size(); fs++) {
		std::vector<unsigned char> sec(sector_size, 0xff);
		for(size_t i = 0; i < 128; i++) {
			size_t idx = fs * 128 + i;
			if(idx < fat.size())
				set_le32(&sec[i * 4], (uint32_t)fat[idx]);
		}
		write_sector(fat_sector_ids[fs], &sec[0], sector_size);
	}

	set_le32(&out[44], (uint32_t)fat_sector_ids.size());
	set_le32(&out[48], dir_ids.empty() ? 0xffffffffu : dir_ids[0]);
	if(touches_mini) {
		set_le32(&out[60], mini_fat_ids.empty() ? 0xffffffffu : mini_fat_ids[0]);
		set_le32(&out[64], (uint32_t)mini_fat_ids.size());
	}
	cfb_set_header_difat(out, fat, fat_sector_ids, difat_sector_ids);

	FILE *fp = fopen(outdb, "wb");
	if(!fp)
		return false;
	bool ok = fwrite(&out[0], 1, out.size(), fp) == out.size();
	fclose(fp);
	return ok;
}

static bool MsgEx_AppendTemplate(const char *template_db, const char *txt, const char *uid, const char *outdb)
{
	CfbFile cfb;
	std::vector<ImportStream> entries;
	std::vector<ImportSection> sections;
	std::vector<int> types;
	std::string parsed_uid;
	unsigned char msg_key[16];
	size_t appended = 0;
	size_t skipped = 0;
	size_t skipped_missing_type = 0;
	size_t skipped_missing_object = 0;
	size_t skipped_missing_stream = 0;
	size_t created_types = 0;
	size_t created_objects = 0;
	bool directory_tree_changed = false;

	if(!cfb_load(template_db, cfb))
		return false;
	if(!read_import_txt(txt, sections, types, &parsed_uid))
		return false;
	if((uid == NULL || *uid == 0) && !parsed_uid.empty())
		uid = parsed_uid.c_str();
	if(uid == NULL || *uid == 0)
		return false;

	if(!load_template_entries_preserve_order(cfb, entries))
		return false;
	if(!template_msg_key(entries, uid, msg_key))
		return false;

	for(size_t i = 0; i < sections.size(); i++) {
		const char *type_name = import_msg_type_name(sections[i].msg_type);
		int type_id;
		int obj_id, data_id, index_id;
		uint32_t offset;

		type_id = find_import_child(entries, 0, type_name, STGTY_STORAGE);
		if(type_id < 0) {
			std::vector<unsigned char> empty;
			type_id = add_cfb_entry(entries, type_name, STGTY_STORAGE, empty);
			link_child(entries, 0, type_id);
			created_types++;
			directory_tree_changed = true;
		}
		obj_id = find_import_child(entries, type_id, sections[i].object, STGTY_STORAGE);
		if(obj_id < 0) {
			std::vector<unsigned char> empty;
			obj_id = add_cfb_entry(entries, sections[i].object, STGTY_STORAGE, empty);
			link_child(entries, type_id, obj_id);
			link_child(entries, obj_id, add_cfb_entry(entries, "Data.msj", STGTY_STREAM, empty));
			link_child(entries, obj_id, add_cfb_entry(entries, "Index.msj", STGTY_STREAM, empty));
			created_objects++;
			directory_tree_changed = true;
		}
		data_id = find_import_child(entries, obj_id, "Data.msj", STGTY_STREAM);
		index_id = find_import_child(entries, obj_id, "Index.msj", STGTY_STREAM);
		if(data_id < 0 || index_id < 0) {
			skipped += sections[i].records.size();
			skipped_missing_stream += sections[i].records.size();
			continue;
		}
		if(data_id >= (int)entries.size() || index_id >= (int)entries.size()) {
			skipped += sections[i].records.size();
			skipped_missing_stream += sections[i].records.size();
			continue;
		}
		offset = (uint32_t)entries[(size_t)data_id].data.size();
		for(size_t j = 0; j < sections[i].records.size(); j++) {
			std::vector<unsigned char> plain = build_plain_record(sections[i].records[j]);
			std::vector<unsigned char> enc = QQMSG_encode_bytes(plain, msg_key);
			put_le32(entries[(size_t)index_id].data, offset);
			entries[(size_t)data_id].data.insert(entries[(size_t)data_id].data.end(), enc.begin(), enc.end());
			offset += (uint32_t)enc.size();
			appended++;
		}
		entries[(size_t)data_id].size = entries[(size_t)data_id].data.size();
		entries[(size_t)index_id].size = entries[(size_t)index_id].data.size();
	}

	if(directory_tree_changed)
		finalize_cfb_directory_tree(entries, 0);
	printf("追加消息: %zu，跳过消息: %zu\n", appended, skipped);
	if(created_types > 0 || created_objects > 0)
		printf("新建消息类型: %zu，新建消息对象: %zu\n", created_types, created_objects);
	if(skipped > 0) {
		printf("跳过原因: 消息类型不存在 %zu，对象不存在 %zu，缺少 Data/Index %zu\n",
		       skipped_missing_type, skipped_missing_object, skipped_missing_stream);
	}
	return write_cfb_template_patch(outdb, cfb, entries);
}
#else
static bool MsgEx_AppendTemplate(const char *template_db, const char *txt, const char *uid, const char *outdb)
{
	(void)template_db;
	(void)txt;
	(void)uid;
	(void)outdb;
	printf("--append-template is not implemented on Windows in this build.\n");
	return false;
}
#endif

static bool MsgEx_ImportTxt(const char *txt, const char *uid, const char *outdb)
{
	std::vector<ImportSection> sections;
	std::vector<int> types;
	std::string parsed_uid;
	unsigned char msg_key[16];
	std::vector<ImportStream> entries;
	std::vector<unsigned char> empty;
	int root;
	int matrix_storage;
	std::map<int, int> type_ids;
	size_t record_count = 0;

	if(!read_import_txt(txt, sections, types, &parsed_uid))
		return false;
	if((uid == NULL || *uid == 0) && !parsed_uid.empty())
		uid = parsed_uid.c_str();
	for(size_t i = 0; i < sections.size(); i++)
		record_count += sections[i].records.size();
	if(uid == NULL || *uid == 0 || record_count == 0)
		return false;
	MD5((char*)"MsgExReverse", 12, (char*)msg_key);

	root = add_cfb_entry(entries, "Root Entry", 5, empty);
	matrix_storage = add_cfb_entry(entries, "Matrix", STGTY_STORAGE, empty);
	link_child(entries, root, matrix_storage);
	link_child(entries, matrix_storage, add_cfb_entry(entries, "Matrix.db", STGTY_STREAM, build_matrix_db(uid, msg_key)));

	for(size_t section_pos = 0; section_pos < sections.size(); section_pos++) {
		int current_type = sections[section_pos].msg_type;
		int current_type_id;
		std::map<int, int>::iterator type_it;
		std::vector<std::vector<unsigned char> > enc_records;

		if(current_type == 0)
			continue;
		type_it = type_ids.find(current_type);
		if(type_it == type_ids.end()) {
			current_type_id = add_cfb_entry(entries, import_msg_type_name(current_type), STGTY_STORAGE, empty);
			link_child(entries, root, current_type_id);
			type_ids[current_type] = current_type_id;
		}else{
			current_type_id = type_it->second;
		}
		int obj_id = add_cfb_entry(entries, sections[section_pos].object, STGTY_STORAGE, empty);
		link_child(entries, current_type_id, obj_id);
		for(size_t j = 0; j < sections[section_pos].records.size(); j++) {
			std::vector<unsigned char> plain = build_plain_record(sections[section_pos].records[j]);
			enc_records.push_back(QQMSG_encode_bytes(plain, msg_key));
		}
		link_child(entries, obj_id, add_cfb_entry(entries, "Data.msj", STGTY_STREAM, build_data_stream(enc_records)));
		link_child(entries, obj_id, add_cfb_entry(entries, "Index.msj", STGTY_STREAM, build_index_stream(enc_records)));
	}
	return write_cfb_file(outdb, entries);
}

static bool output_name_for_official_qq(const char *path)
{
	const char *base = strrchr(path, '/');
#ifdef _WIN32
	const char *base2 = strrchr(path, '\\');
	if(base2 && (!base || base2 > base))
		base = base2;
#endif
	base = base ? base + 1 : path;
	size_t len = strlen(base);
	const char suffix[] = "MsgEx.db";
	size_t suffix_len = sizeof(suffix) - 1;
	return len >= suffix_len && strcmp(base + len - suffix_len, suffix) == 0;
}

static void warn_official_qq_output_name(const char *path)
{
	if(!output_name_for_official_qq(path))
		printf("提示：官方 QQ 可能要求文件名以 MsgEx.db 结尾，否则无法打开。\n");
}


/* QQmsg <MsgEx.db> [uid] [output] */
int main(int argc, char* argv[])
{
	TNode *node;
	char *pUid = NULL;
	char *pMatrix;
	unsigned int pMatrixLen;
	char UidMd5[16];
	char *pCRK;
	int pCRKLen;
	int pLen=0;
	char *pUser=NULL;
	char strUid[20], strPath[512];
	time_t t;
	char fname[40];

//	printf("Hello World!\n");
	if(argc < 2){
		printf("Usage: %s <MsgEx.db> [QQ-Number]\n", argv[0]);
		printf("       %s --import <input.txt> <QQ-Number> <output.db>\n", argv[0]);
		printf("       %s --append-template <template.db> <input.txt> <QQ-Number> <output.db>\n", argv[0]);
		return -1;
	}

	if(strcmp(argv[1], "--append-template") == 0) {
		if(argc < 6) {
			printf("Usage: %s --append-template <template.db> <input.txt> <QQ-Number> <output.db>\n", argv[0]);
			return -1;
		}
		if(!MsgEx_AppendTemplate(argv[2], argv[3], argv[4], argv[5])) {
			printf("Failed to append TXT file to template: %s\n", argv[3]);
			return -1;
		}
		warn_official_qq_output_name(argv[5]);
		printf("MsgEx.db 已生成: %s\n", argv[5]);
		return 0;
	}

	if(strcmp(argv[1], "--import") == 0) {
		if(argc < 5) {
			printf("Usage: %s --import <input.txt> <QQ-Number> <output.db>\n", argv[0]);
			return -1;
		}
		if(!MsgEx_ImportTxt(argv[2], argv[3], argv[4])) {
			printf("Failed to import TXT file: %s\n", argv[2]);
			return -1;
		}
		warn_official_qq_output_name(argv[4]);
		printf("MsgEx.db 已生成: %s\n", argv[4]);
		return 0;
	}

	if(argc >= 3)
	{
		strcpy(strUid, argv[2]);
		snprintf(strPath, sizeof(strPath), "%s", argv[1]);
	}else
	{
		/* try to get QQ number from path */
		memset(strUid, 0, sizeof(strUid));
		memset(strPath, 0, sizeof(strPath));

		if(Find_QQPath_Number(argv[1], strPath, strUid) == NULL){
			printf("Please tell me the QQ number\n");
			return -1;
		}
	}
	pUid = strUid;


	if(argc >= 4)
		pUser = argv[3];


	TNODE_INIT(Tree);
	Tree.type = 1;
	sprintf(Tree.name, "MsgEx.db");
	TParent = &Tree;

	if(MsgEx_OpenStorageFile(strPath) < 0)
		return -1;

//	TNode_traverse(&Tree);

	node = TNode_find(&Tree, "Matrix.db");
	if(!node){
		printf("Failed to open Matrix.db!\n");
		return -1;
	}
	pMatrix = node->data;
	pMatrixLen = node->len;
	MsgEx_DecodeMatrixDB(pMatrix, pMatrixLen);
	//MsgEx_DumpHex(pMatrix, pMatrixLen);

	pCRK = MsgEx_FindMatrixDB(pMatrix, pMatrixLen, "CRK", &pCRKLen);
	//printf("CRKLen=%d\n", pCRKLen);
	//MsgEx_DumpHex(pCRK, pCRKLen);


	MD5(pUid, strlen(pUid), UidMd5);
	//printf("UidMd5:\n");
	//MsgEx_DumpHex(UidMd5, 16);

	pLen = 16;
	QQMSG_decode(pCRK, pCRKLen, UidMd5, pMsgExKey, &pLen);
	//msgex_decode(pCRK, pCRKLen, pMsgExKey, UidMd5);
//	printf("pMsgExKey:\n");
//	MsgEx_DumpHex(pMsgExKey, 16);

/*
	//show QQ message from certain user
	node = TNode_find(&Tree, pUser);
	if(node)
		MsgEx_DumpMsg(node);
	else
		printf("Tnode not found\n");
*/

	sprintf(fname, "%s.txt", pUid);
	fpout = fopen(fname, "w");
	if(fpout == NULL){
		printf("Can't open file for writing\n");
		fpout = stdout;
	}
	printf("处理中，请稍候...\n");
	fprintf(fpout, "\n");
	fprintf(fpout, "==================================================\n");
	fprintf(fpout, "本文件由QQMsg生成\n");
	fprintf(fpout, "友情提醒：查看别人的聊天记录属于不道德行为！\n");
	fprintf(fpout, "本人不对此软件产生的任何后果负责！\n");
	fprintf(fpout, "\n");
	fprintf(fpout, "QUQU<quhongjun@msn.com>\n");
	fprintf(fpout, "2006/12/28\n");
	fprintf(fpout, "\n");
	fprintf(fpout, "项目维护地址：https://github.com/QQBackup/MsgEx\n");
	fprintf(fpout, "LY<ly-niko@qq.com>\n");
	fprintf(fpout, "2023/11/10\n");
	fprintf(fpout, "==================================================\n");
	fprintf(fpout, "\n\n");
	
	t = time(0);
	fprintf(fpout, "用户：%s\n\n", pUid); 
	fprintf(fpout, "生成时间：%s\n", strtime(&t));

	MsgEx_DumpMsg(&Tree);

	printf("聊天记录已保存至: %s\n", fname);
	fclose(fpout);
	return 0;
}
