#ifndef __PEINFO_H__
#define __PEINFO_H__

typedef struct  peinfo
{
	//dos头
	IMAGE_DOS_HEADER dosHeader;
	//nt头
	IMAGE_NT_HEADERS ntHeader;

	//节区
	IMAGE_SECTION_HEADER *sections_table;

	//导入表
	DWORD dwIatOffset;
	//当前的位置
	DWORD curPos;
	//oep在文件中的地址可用这个读取指向
	DWORD dwRvaOep;

	//指向SECTION_TABLE的起始地址
	DWORD dwSec;
	//是否已经加载
	BOOL bLoad;
} peinfo;


#endif
