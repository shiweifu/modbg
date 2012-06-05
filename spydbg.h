#ifndef __SPYDBG_H__
#define __SPYDBG_H__

// 从远程线程中读取一段字符串，它是对ReadChar函数的封装
WCHAR * ReadRemoteString(HANDLE process, LPVOID address, WORD length, WORD unicode);

// 从目标进程指定地址中读取一个字符
WCHAR ReadCharW(HANDLE process, LPVOID address);
CHAR ReadCharA(HANDLE process, LPVOID address);

// 从远程线程中读取一段字符串，以零结尾，它是对ReadChar函数的封装
WCHAR * ReadRemoteSZ(HANDLE process, LPVOID address, WORD unicode);
// 从目标进程中读取一个地址.
VOID * ReadRemotePtr(HANDLE process, LPVOID address);
// 处理DEBUG_EVENT消息结构体


//断点系列相关函数
BOOL BreakProcessPtr(HANDLE process, LPVOID address);
BOOL UnBreakProcessPtr(HANDLE process, LPVOID address);

BOOL SingleStepBreak(HANDLE hProcess,DWORD dwThreadId,LPVOID addr);

int RandomBpTableIndex();

//以下定义结构体


#endif
