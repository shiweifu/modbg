#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <assert.h>

#include "peinfo.h"
#include "moDbg.h"


//读取DOS头，并判断是否是一个PE文件
//如果不是个合法的PE文件，则失败
BOOL LoadDosHeader(FILE *f,peinfo *p)
{
	IMAGE_DOS_HEADER *dh;
	dh = &p->dosHeader;

	assert(f);
	assert(p);

	if(fgetpos(f,(fpos_t*)&p->curPos) != 0)
	{
		SETERROR("get pos error in LoadDosHeader");
		return FALSE;
	}

	if(fseek(f,0,SEEK_SET) != 0)
	{

		SETERROR("Set Seek Error in LoadDosHeader");
		return FALSE;
	}

	if (!fread(dh,sizeof(*dh),1,f))
	{
		SETERROR("Fread Error in LoadDosHeader");
		fseek(f,p->curPos,SEEK_SET);
		return FALSE;
	}

	if(strncmp((char*)&dh->e_magic,"MZ",2) != 0)
	{
		SETERROR("It's not a PE file");
		fseek(f,p->curPos,SEEK_SET);
		return FALSE;
	}
	return TRUE;
}



BOOL LoadNtHeader(FILE *f,peinfo *pf)
{
	IMAGE_NT_HEADERS *nh = &pf->ntHeader;

	if(pf->dosHeader.e_lfanew == 0L)
	{
		SETERROR("Please Load DosHeader First.");
		return FALSE;
	}

	if(fseek(f,pf->dosHeader.e_lfanew,SEEK_SET) != 0)
	{

		SETERROR("Set Seek Error in LoadDosHeader");
		return FALSE;
	}

	if(!fread(nh,sizeof(*nh),1,f))
	{
		SETERROR("read nt header error\n");
		return FALSE;
	}

	//nh->OptionalHeader

	return TRUE;
}

//RVA转换PE OFFSET
DWORD RVA2Offset(peinfo *pi, DWORD dwRVA)
{
	int i;
	if(!pi->bLoad)
	{
		SETERROR("not loaded pe.");
		return FALSE;
	}

	for(i = 0; i < pi->ntHeader.FileHeader.NumberOfSections; i++)
	{
		if(dwRVA >= pi->sections_table[i].VirtualAddress && 
			dwRVA < (pi->sections_table[i].VirtualAddress + pi->sections_table[i].SizeOfRawData))
		{
			return pi->sections_table[i].PointerToRawData + (dwRVA - pi->sections_table[i].VirtualAddress);
		}
	}

	SETERROR("not found pe.");
	return FALSE;
}

void my_apply(FILE *ff, IMAGE_IMPORT_DESCRIPTOR *cl,peinfo *pi)
{
	fpos_t oldPos;
	DWORD offset = 0;
	fpos_t thunkPos = 0;
	char *name;//[NAME_LEN] = {0};
//	IMAGE_IMPORT_BY_NAME funcName;
	int i;
//	int j;
	IMAGE_THUNK_DATA thunkData;
	 WORD    Hint;

	name = (char*)malloc(NAME_LEN);

	fgetpos(ff,&oldPos);

	offset = RVA2Offset(pi,cl->Name);
	fseek(ff,offset,SEEK_SET);

	for(i = 0; ; i++)
	{
		name[i] = fgetc(ff);
		if(name[i] == 0)
		{
			break;
		}
	}
	printf("The moudel name: %s\n",name);

	offset = RVA2Offset(pi,cl->OriginalFirstThunk);
 	fseek(ff,offset,SEEK_SET);

	//~ if(fread(&thunkData,1,sizeof(thunkData),ff) != sizeof(thunkData))
	//~ {
	//~ SETERROR("not read data");
	//~ __asm int 3
	//~ }

	memset(name,0,NAME_LEN);

	while(1)
	{
		fread(&thunkData,1,sizeof(thunkData),ff);// == sizeof(thunkData)
		fgetpos(ff,&thunkPos);
		if(thunkData.u1.Ordinal == 0)
		{
			break;
		}

		if(thunkData.u1.Ordinal & IMAGE_ORDINAL_FLAG32)
		{
			//printf("it's a number\n");
			printf("    [%03d]  ---  Number: %04d    Name: <NULL>\n",  1, thunkData.u1.Ordinal & 0xFFFF);
		}
		else
		{
			Hint = 0;
			offset = RVA2Offset(pi,thunkData.u1.AddressOfData);
			fseek(ff,offset,SEEK_SET);
			fread(&Hint,1,sizeof(Hint),ff);
			//fread(name,1,NAME_LEN,ff);
			for(i = 0; ; i++)
			{
				name[i] = fgetc(ff);
				if(name[i] == 0)
				{
					goto JMP_OUT;
				}
			}
JMP_OUT:
			printf("    [%03d]  ---  Number: %04d    Name: %s\n", 1, Hint, name);
			memset(name,0,NAME_LEN);
			fsetpos(ff,&thunkPos);
		}
	}
	free(name);
	fflush(ff);
	fsetpos(ff,&oldPos);
}

BOOL IAT_Map(FILE *f,peinfo *pf,void apply(FILE *ff, IMAGE_IMPORT_DESCRIPTOR *cl,peinfo *pi))
{

	IMAGE_IMPORT_DESCRIPTOR iid;

	assert(pf);
	if(apply == NULL)
	{
		SETERROR("not have apply func");
		return FALSE;
	}
	if (fseek(f,pf->dwIatOffset,SEEK_SET) != 0)
	{
		SETERROR("seek IAT pos error");
		return FALSE;
	}

	while (1)
	{
		if(fread(&iid,1,sizeof(IMAGE_IMPORT_DESCRIPTOR),f) !=sizeof(IMAGE_IMPORT_DESCRIPTOR))
		{
			SETERROR("read IID ERROR");
			return FALSE;
		}
		if(iid.Name == 0)
		{
			//到结尾了
			break;
		}
		apply(f,&iid,pf);
	}

	//apply()	
	return TRUE;
}

BOOL LoadPeinfo(FILE *f, peinfo *pf)
{

	int i = 0;
	fpos_t newPos = 0;

	if (!LoadDosHeader(f,pf))
	{
		printf("%s\r\n",err);
		return FALSE;
	}

	if (!LoadNtHeader(f,pf))
	{
		printf("%s\r\n",err);
		return FALSE;
	}

	fgetpos(f,(fpos_t *)&pf->curPos);

	newPos = pf->dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);

	fsetpos(f,&newPos);

	//读取节表
	pf->sections_table = (IMAGE_SECTION_HEADER *)
		malloc(sizeof(IMAGE_SECTION_HEADER) * pf->ntHeader.OptionalHeader.NumberOfRvaAndSizes);
	for (i = 0; i < pf->ntHeader.FileHeader.NumberOfSections; i++)
	{
		fread(&pf->sections_table[i],sizeof(IMAGE_SECTION_HEADER),1,f);
	}

	fsetpos(f,(fpos_t *)&pf->curPos);

	pf->dwRvaOep = RVA2Offset(pf,
		pf->ntHeader.OptionalHeader.AddressOfEntryPoint);

	pf->dwIatOffset =RVA2Offset(pf,
		pf->ntHeader.OptionalHeader.DataDirectory[1].VirtualAddress);

#ifdef __DEBUG__
	__asm int 3
#endif
		pf->bLoad = TRUE;
	return TRUE;
}
