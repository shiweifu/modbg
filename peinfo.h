#ifndef __PEINFO_H__
#define __PEINFO_H__

typedef struct  peinfo
{
	//dosͷ
	IMAGE_DOS_HEADER dosHeader;
	//ntͷ
	IMAGE_NT_HEADERS ntHeader;

	//����
	IMAGE_SECTION_HEADER *sections_table;

	//�����
	DWORD dwIatOffset;
	//��ǰ��λ��
	DWORD curPos;
	//oep���ļ��еĵ�ַ���������ȡָ��
	DWORD dwRvaOep;

	//ָ��SECTION_TABLE����ʼ��ַ
	DWORD dwSec;
	//�Ƿ��Ѿ�����
	BOOL bLoad;
} peinfo;


#endif
