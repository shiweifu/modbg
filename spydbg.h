#ifndef __SPYDBG_H__
#define __SPYDBG_H__

// ��Զ���߳��ж�ȡһ���ַ��������Ƕ�ReadChar�����ķ�װ
WCHAR * ReadRemoteString(HANDLE process, LPVOID address, WORD length, WORD unicode);

// ��Ŀ�����ָ����ַ�ж�ȡһ���ַ�
WCHAR ReadCharW(HANDLE process, LPVOID address);
CHAR ReadCharA(HANDLE process, LPVOID address);

// ��Զ���߳��ж�ȡһ���ַ����������β�����Ƕ�ReadChar�����ķ�װ
WCHAR * ReadRemoteSZ(HANDLE process, LPVOID address, WORD unicode);
// ��Ŀ������ж�ȡһ����ַ.
VOID * ReadRemotePtr(HANDLE process, LPVOID address);
// ����DEBUG_EVENT��Ϣ�ṹ��


//�ϵ�ϵ����غ���
BOOL BreakProcessPtr(HANDLE process, LPVOID address);
BOOL UnBreakProcessPtr(HANDLE process, LPVOID address);

BOOL SingleStepBreak(HANDLE hProcess,DWORD dwThreadId,LPVOID addr);

int RandomBpTableIndex();

//���¶���ṹ��


#endif
