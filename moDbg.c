#include "global_header.h"

#include "libdasm.h"
#include "list.h"
#include "moDbg.h"
#include "ldasm.h"

//全局对象
char err[ERR_LEN];

PDEBUGGEE moDbg = NULL;


CMD_HANDLER_ENTRY CommandTable[COMMAND_TABLE_LEN] = {
	CMD_ENTRY (open, 1, "open : open a file by path"),
	CMD_ENTRY (debug, 1, "debug : start debug,the execute must was opened"),
	CMD_ENTRY (disasm, 1, "disasm : open a file by path"),
	CMD_ENTRY (close, 1, "close : close the debugging file"),
	CMD_ENTRY (go, 1, "go : run to break"),
	CMD_ENTRY (bp, 1, "bp : break at address"),
	CMD_ENTRY (hbp, 1, "hbp : hard break at address"),
	CMD_ENTRY (mbp, 1, "mbp : memory break at address"),
	CMD_ENTRY (dm, 0, "dm : display memory contents"),
	CMD_ENTRY (step, 0, "step : step into step"),

	CMD_ENTRY (exit, 1, "exit : exit debugger"),
	CMD_ENTRY (help, 1, "help"),
	CMD_ENTRY (attach, 1, "attach : attach the process"),
	CMD_ENTRY (now, 1, "now : display current debugger state"),
	CMD_ENTRY (ver, 0, "ver : displays version information"),

	CMD_ENTRY (tasklist, 0, "tasklist : displays list of the processes in the system"),
	CMD_ENTRY (process, 1, "process : earches the process by its name or PID"),
	CMD_ENTRY (thread, 1, "thread : seacrhes the thread by its name or TID"),
	CMD_ENTRY (taskkill, 1, "taskkill : kills the process by its PID"),


	CMD_END
};

EventMsg EventFuncs[] = 
{
	{EXCEPTION_DEBUG_EVENT,
	OnDebugEvent,
	OutputExceptionEvent},

	{CREATE_THREAD_DEBUG_EVENT,
	OnCreateThreadEvent,
	OutputCreateThreadEvent},

	{CREATE_PROCESS_DEBUG_EVENT,
	OnCreateProcessDebugEvent,
	OutputCreateProcessEvent},

	{EXIT_THREAD_DEBUG_EVENT,
	OnExitThreadDebugEvent,
	OutputExitThreadEvent},

	{EXIT_PROCESS_DEBUG_EVENT,
	OnExitProcessDebugEvent,
	OutputExitProcessEvent},

	{LOAD_DLL_DEBUG_EVENT,
	OnLoadDllDebugEvent,
	OutputDllLoadEvent},

	{UNLOAD_DLL_DEBUG_EVENT,
	OnUnLoadDllDebugEvent,
	OutputDllUnLoadEvent},

	{OUTPUT_DEBUG_STRING_EVENT,
	OnOutputDebugStringEvent,
	NULL},

	{RIP_EVENT,
	OnRipEvent,
	NULL},
	{0,0}
};

//一个通用的参数实现
ARG* __getarg (int argc, 
			   char** argv, 
			   int n)
{
	//HANDLE heap;
	ARG *arg;
	char *pstr;

	//hinit();
	//halloc(256);

	if (n > argc)
	{
		printf("* Not enough arguments for command [expected arg %d, found %d args total]\n", n, argc);
		ExitThread(0);
		return NULL;
	}

	//
	// Recognize type
	//

	arg = (ARG*) malloc (sizeof(ARG));

	if (isdigit(argv[n][0]))
	{
		// dword

		arg->type = AT_DWORD;

		if (argv[n][0] == '0' && argv[n][1] == 'x')
		{
			sscanf (&argv[n][2], "%x", &arg->dw);
		}
		else if(argv[n][strlen(argv[n])-1] == 'h')
		{
			argv[n][strlen(argv[n])-1] = 0;
			sscanf (argv[n], "%x", &arg->dw);
		}
		else
		{
			arg->dw = atoi (argv[n]);
		}

		return arg;
	}

	// string

	arg->type = AT_STRING;

	pstr = argv[n];

	if (*pstr == '"')
	{
		pstr++;
		if (pstr[strlen(pstr)-1] == '"')
		{
			pstr[strlen(pstr)-1] = 0;
		}
		else
		{
			printf("* Argument not valid for string: arg=%d, [%s]\n", n,argv[0]);
			printf("* The error was: \" quote mismatch\n");
			free (arg);
			//ExitThread(0);
			return NULL;
		}
	}
	else
	{
		if (pstr[strlen(pstr)-1] == '"')
		{
			printf("* Argument not valid for string: arg=%d, [%s]\n", n,argv[0]);
			printf("* The error was: \" quote mismatch\n");
			//			hfree (arg);
			ExitThread(0);
			return NULL;
		}
	}

	if (*pstr == '\'')
	{
		pstr++;
		if (pstr[strlen(pstr)-1] == '\'')
		{
			pstr[strlen(pstr)-1] = 0;
		}
		else
		{
			printf("* Argument not valid for string: arg=%d, [%s]\n", n,argv[0]);
			printf("* The error was: ' quote mismatch\n");
			free (arg);
			ExitThread(0);
			return NULL;
		}
	}
	else
	{
		if (pstr[strlen(pstr)-1] == '\'')
		{
			printf("* Argument not valid for string: arg=%d, [%s]\n", n,argv[0]);
			printf("* The error was: ' quote mismatch\n");
			free (arg);
			ExitThread(0);
			return NULL;
		}
	}


	strncpy (arg->str, pstr, sizeof(arg->str)-1);
	return arg;
}

//干活的函数
DWORD WINAPI DebugThreadProc(
							 LPVOID lpParameter
							 )
{
	DWORD endDisposition;
	DEBUG_EVENT debugEvent = { 0 } ;

	STARTUPINFO startupInfo={0}; 
	PROCESS_INFORMATION processInfo = {0};

	HANDLE hThread;
	DWORD dwThreadId;

	BOOL res;
	PDEBUGGEE dbg;
	char *name = (char *)lpParameter;

	//	res = ;
	if (!CreateProcess(NULL, name, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &startupInfo, &processInfo))
	{ 
		GetLastError();
		SETERROR("Create Debug Process Error.Please check the execute name.");
		return 0;
	}

	dbg = (PDEBUGGEE) malloc(sizeof(DEBUGGEE));
	memset(dbg,0,sizeof(DEBUGGEE));

	dbg->hProcess = processInfo.hProcess;
	dbg->dwProcessId = processInfo.dwProcessId;
	strcpy(dbg->name,name);


	dbg->hProcess = processInfo.hProcess;
	dbg->hDebugThread = processInfo.hThread;
	dbg->dwDebugThreadId = processInfo.dwThreadId;

	dbg->hMutex = CreateMutex(NULL,FALSE,NULL);

	moDbg = dbg;
	Sleep(500);

	endDisposition = DBG_CONTINUE;

	for(;endDisposition != 0;)
	{
		if (!WaitForDebugEvent(&debugEvent, INFINITE))
		{
			SETERROR("WaitForDebugEvent failed\n");
			GetLastError();
			__asm int 3
				break;
		}
		endDisposition = ProcessEvent(&debugEvent,moDbg);
		if (0 == endDisposition) break;
		if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, endDisposition))
		{
			SETERROR("ContinueDebugEvent failed\n");
			GetLastError();
			break;
		};
		if(debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
		{
			free(moDbg);
			moDbg = NULL;
			goto END;
		}
	}
END:
	return 0;
}

// 处理DEBUG_EVENT
// name: ProcessEvent
// @param
// dbgEvent: 指向DEBUG_EVENT的执行
// @return
// 处理完毕，继续执行 
DWORD ProcessEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{
	int i = 0;
	//printf("%s%d.%d\n", "New event generated by PID.TID=" , 
	//	dbgEvent->dwProcessId , dbgEvent->dwThreadId);

	while(EventFuncs[i].PeFun != NULL)
	{
		if(EventFuncs[i].dwEventId == dbgEvent->dwDebugEventCode)
		{
			goto END_PROC;
		}
		i++;
	}
END_PROC:

#ifdef __DISPLAY__
	if(EventFuncs[i].Ote != NULL)
	{
		//			OUTPUT_DEBUGEVENT_INFO(i,stdout)
		EventFuncs[i].Ote(dbgEvent,stdout);
	}
#endif
	return EventFuncs[i].PeFun(dbgEvent,dbg);
}


VOID
DbgCorrectPatchedMemory(
						PDEBUGGEE dbg,
						ULONG VirtualAddressStart,
						ULONG Size,
						PVOID Buffer
						)
{
	return;
}

//通过文件名创建一个调试进程
PDEBUGGEE
DbgOpen(
		char *name
		)
{
	//这个函数现在没用



	//STARTUPINFO startupInfo={0}; 
	//PROCESS_INFORMATION processInfo = {0};

	//HANDLE hThread;
	//DWORD dwThreadId;
	//BOOL res;
	//PDEBUGGEE dbg;

	//res = CreateProcess(NULL, name, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &startupInfo, &processInfo);
	//if (FALSE == res)
	//{ 
	//	SETERROR("Create Debug Process Error.Please check the execute name.");
	//	return NULL;
	//}

	//dbg = (PDEBUGGEE) malloc(sizeof(DEBUGGEE));
	//memset(dbg,0,sizeof(DEBUGGEE));

	//dbg->hProcess = processInfo.hProcess;
	//dbg->dwProcessId = processInfo.dwProcessId;
	//strcpy(dbg->name,name);

	//hThread = CreateThread(NULL,0,DebugThreadProc,dbg,CREATE_SUSPENDED,&dwThreadId);

	//if (hThread == NULL)
	//{
	//	SETERROR("Create Debug Thread Error.");
	//	return NULL;
	//}

	//dbg->hProcess = processInfo.hProcess;
	//dbg->hDebugThread = hThread;
	//dbg->dwDebugThreadId = dwThreadId;

	//ResumeThread(dbg->hDebugThread);

	//return dbg;
	return NULL;
}

VOID
DbgClear(
		 PDEBUGGEE dbg
			)
{
	//	dbg->ThreadHandleTable

	if(dbg)
	{
		if(dbg->ThreadHandleTable)
		{
			List_map(dbg->ThreadHandleTable,DestroyThreadHandle,NULL);
			List_free(&dbg->ThreadHandleTable);
			dbg->ThreadHandleTable = NULL;
		}

		if(dbg->MemTable)
		{	
			//销毁其中所有成员所分配的内存
			List_map(dbg->MemTable,DestroyThreadHandle,NULL);
			List_free(&dbg->MemTable);
			dbg->MemTable = NULL;
		}
		free(dbg);
	}
}

//依附加载
PDEBUGGEE
DbgAttach(
		  ULONG dwProcessId
		  )
{
	return NULL;
}

VOID
DbgDetach(
		  PDEBUGGEE dbg
		  )
{
}


VOID
DbgFastDetach(
			  PDEBUGGEE dbg
			  )
{
}

BOOL
DbgLookupProcessName(
					 //	PSYSTEM_PROCESSES_INFORMATION Buffer OPTIONAL,
					 ULONG dwProcessId,
					 char *ProcessNameBuffer,
					 ULONG MaxLength
					 )
{
	return FALSE;
}

BOOL
DbgUserExceptionDispatcherHook(
							   PDEBUGGEE dbg
							   )
{

	return FALSE;
}

VOID
DbgUserExceptionDispatcherUnhook(
								 PDEBUGGEE dbg
								 )
{
}



BOOL
DbgLookupUserBreakPoint(
						PDEBUGGEE dbg,
						ULONG Address)
{
	int i;

	for (i=0; i<MAX_BPS; i++)
	{
		if (dbg->bps[i].Present == 0)
		{
			continue;
		}
		if (dbg->bps[i].AddressLow == Address)
		{
			break;
		}

	}
	if(i == MAX_BPS)
	{
		return FALSE;
	}
	dbg->cur_bps = &dbg->bps[i];
	return TRUE;
}

INT
DbgSetSoftwareBreakpoint(
						 PDEBUGGEE dbg,
						 ULONG Address,
						 BOOLEAN OneShot
						 )
{
	ULONG t;
	UCHAR OldByte = 0;
	ULONG len;
	int i;
	PUCHAR bpbase;

	if (!(ReadProcessMemory (dbg->hProcess, (LPCVOID)Address, &OldByte, 1, &t) &&
		WriteProcessMemory (dbg->hProcess, (LPVOID)Address, "\xCC", 1, &t)))
	{
		//		FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
		return -1;
	}

	for (i=0; i<MAX_BPS; i++)
	{
		if (dbg->bps[i].Present == 0)
		{
			dbg->bps[i].Present = 1;
			//dbg->bps[i].Hardware = 0;
			dbg->bps[i].BreakType = BREAK_TYPE_SOFT;

			dbg->bps[i].AddressLow = Address;
			dbg->bps[i].OldByte = OldByte;
			dbg->bps[i].OneShot = OneShot;

			printf("Soft BreakPoint in %X\n",Address);

			if (!OneShot)
			{
				UCHAR buffer[SIZEOF_BP_BUFFER];

				if ( !ReadProcessMemory (dbg->hProcess, (LPCVOID)Address, buffer, SIZEOF_BP_BUFFER, &t))
				{
					//					FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
					return -1;
				}

				buffer[0] = OldByte;

				len = size_of_code (buffer);
				bpbase = (PUCHAR) dbg->BreakPointBuffers;

				buffer[len] = 0xE9;
				*(ULONG*)&buffer[len+1] = (Address + len) - ((ULONG)bpbase + SIZEOF_BP_BUFFER*i + len) - 5;

				if ( !WriteProcessMemory (dbg->hProcess, bpbase + SIZEOF_BP_BUFFER*i, buffer, SIZEOF_BP_BUFFER, &t))
				{
					//					FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
					return -1;
				}

				dbg->bps[i].AddressOfBuffer = (ULONG)bpbase + SIZEOF_BP_BUFFER*i;
			}

			return i;
		}
	}

	//lstrcpy (cdbg_last_err, "Not enough slots");
	return -1;
}


BOOL
DbgRemoveSoftwareBreakpoint(
							PDEBUGGEE dbg,
							ULONG Address,
							INT Number
							)
{
	int i;
	ULONG t;
	if (Address)
	{
		Number = -1;
		for (i=0; i<MAX_BPS; i++)
		{
			if (dbg->bps[i].Present == 1 && dbg->bps[i].AddressLow == Address)
			{
				Number = i; break;
			}
		}
	}

	if (Number != -1)
	{
		dbg->bps[Number].Present = 0;


		if(!WriteProcessMemory (dbg->hProcess, (LPVOID)dbg->bps[Number].AddressLow, &dbg->bps[Number].OldByte, 1, &t))
		{
			//			FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
			return FALSE;
		}
		
		dbg->BreakContext.Eip -= 1;
		
		return TRUE;
	}

	//	lstrcpy (cdbg_last_err, "Not found");
	SETERROR("Not found The Soft BreakPoint");
	return FALSE;
}

BOOL
DbgDisableSoftwareBreakpoint(
							 PDEBUGGEE dbg,
							 ULONG Address,
							 INT Number
							 )
{
	/*++
	Remove software breakpoint
	--*/
	{
		int i;
		ULONG t;

		if (Address)
		{
			Number = -1;
			for (i=0; i<MAX_BPS; i++)
			{
				if (dbg->bps[i].Present == 1 && dbg->bps[i].AddressLow == Address)
				{
					Number = i; break;
				}
			}

		}

		if (Number != -1)
		{
			dbg->bps[Number].Disabled = 1;

			if(!WriteProcessMemory (dbg->hProcess, (LPVOID)dbg->bps[Number].AddressLow, &dbg->bps[Number].OldByte, 1, &t))
			{
				//FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
				return FALSE;
			}

			return TRUE;
		}

		//    lstrcpy (cdbg_last_err, "Not found");
		SETERROR("Not Found");
		return FALSE;
	}
}

BOOL
DbgEnableSoftwareBreakpoint(
							PDEBUGGEE dbg,
							ULONG Address,
							INT Number
							)
{
	int i;
	ULONG t;
	if (Address)
	{
		Number = -1;
		for (i=0; i<MAX_BPS; i++)
		{
			if (dbg->bps[i].Present == 1 && dbg->bps[i].AddressLow == Address)
			{
				Number = i; break;
			}
		}
	}

	if (Number != -1)
	{
		dbg->bps[Number].Disabled = 0;

		if(!WriteProcessMemory (dbg->hProcess, (LPVOID)dbg->bps[Number].AddressLow, "\xCC", 1, &t))
		{
			//FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
			return FALSE;
		}

		return TRUE;
	}

	//lstrcpy (cdbg_last_err, "Not found");
	SETERROR("Not Found");
	return FALSE;
}

INT
DbgSetHardwareBreakpoint(
						 PDEBUGGEE dbg,
						 ULONG Address,
						 BOOLEAN OneShot,
						 UCHAR Type,
						 UCHAR Length
						 )
{
	int i;
	UINT r;
	CONTEXT 	ctx = {CONTEXT_DEBUG_REGISTERS};
	BOOL a;
	REG_DR7 dr7;
	ULONG len;
	PUCHAR bpbase;
	List_T hThreadHead;
	ThreadTableNode *tn;


	for (i=0; i<4; i++)
	{

		if (dbg->hws[i] == 0)
		{

			//查找未设置的硬件断点位置

			for (r=0; r<MAX_BPS; r++)
			{
				if (dbg->bps[r].Present == 0)
				{
					dbg->hws[i] = &dbg->bps[r];
					break;
				}
			}

			dbg->hws[i]->Present = 1;
			//			dbg->hws[i]->Hardware = 1;
			dbg->hws[i]->BreakType = BREAK_TYPE_HARDWARD;
			dbg->hws[i]->AddressLow = Address;
			dbg->hws[i]->Type = Type;
			dbg->hws[i]->OneShot = OneShot;
			dbg->hws[i]->BpNum = i;



			//for (j=0; j<dbg->nThreads; j++)
			//for (hThread = List_toArray(ThreadHandleTable);;hThread++)
			for (hThreadHead = dbg->ThreadHandleTable;
				hThreadHead!= NULL; hThreadHead=hThreadHead->rest)
			{
				tn = (ThreadTableNode*)hThreadHead->first;


				a = GetThreadContext (tn->hThread, &ctx);


				dr7.Raw = ctx.Dr7;

				switch (i)
				{
				case 0:
					dr7.Len0 = Length - 1;
					dr7.Local0 = 1;
					dr7.ReadWrite0 = Type;
					ctx.Dr0 = Address;
					break;
				case 1:
					dr7.Len1 = Length - 1;
					dr7.Local1 = 1;
					dr7.ReadWrite1 = Type;
					ctx.Dr1 = Address;
					break;
				case 2:
					dr7.Len2 = Length - 1;
					dr7.Local2 = 1;
					dr7.ReadWrite2 = Type;
					ctx.Dr2 = Address;
					break;
				case 3:
					dr7.Len3 = Length - 1;
					dr7.Local3 = 1;
					dr7.ReadWrite3 = Type;
					ctx.Dr3 = Address;
					break;
				}

				ctx.Dr7 = dr7.Raw;

				a = SetThreadContext (tn->hThread, &ctx);

				if (!OneShot)
				{
					UCHAR buffer[SIZEOF_BP_BUFFER];
					ULONG t;

					if ( !ReadProcessMemory (dbg->hProcess, (LPCVOID)Address, buffer, SIZEOF_BP_BUFFER, &t))
					{
						//						FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
						return -1;
					}

					len = size_of_code (buffer);
					bpbase = (PUCHAR) dbg->BreakPointBuffers;

					buffer[len] = 0xE9;
					*(ULONG*)&buffer[len+1] = (Address + len) - ((ULONG)bpbase + SIZEOF_BP_BUFFER*r + len) - 5;

					if ( !WriteProcessMemory (dbg->hProcess, bpbase + SIZEOF_BP_BUFFER*r, buffer, SIZEOF_BP_BUFFER, &t))
					{
						//						FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
						return -1;
					}

					dbg->bps[r].AddressOfBuffer = (ULONG)bpbase + SIZEOF_BP_BUFFER*r;

				} // if !OneShot

			} // for j=nThreads

			return r;

		} // if hws==0

	} // for
	return 0;
}

VOID
DbgDisasm(					
		  PDEBUGGEE dbg,
		  ULONG Address,
		  INT Count
		  )
{
	int i = 0;
	char buff[16] = {0};
	char string[32] = {0};
	SIZE_T n = 0;
	SIZE_T sum = 0;
	INSTRUCTION inst;


	if(Address == 0)
	{
		Address = dbg->BreakContext.Eip;
		Count = 20;
	}
	else if(Count == 0)
	{
		Count = 20;
	}

	for(i = 0; i < Count; i++)
	{
		ReadProcessMemory(dbg->hProcess,(LPVOID)(Address + sum),buff,16,&n);
		n = get_instruction(&inst, buff, MODE_32);
		get_instruction_string(&inst, FORMAT_INTEL, 0, string, 32);
		printf("%p : %s\n", (Address + sum) ,string);
		sum += n;

	}

	//更新内存分页信息用于判断内存断点是否可读，但以调试方式启动程序默认具有最高权限
	//UpdateMemTable(dbg);

	//List_map(dbg->MemTable,FindMemNodeMemory,&Address);


	//这里不需要判断，调试器有最高权限
	//~ if(dbg->pCurrentMemNode->Protect)
	//~ {

	//}

}

// 删除硬件断点

// name: DbgRemoveHardwareBreakpoint

// @param

// dbg: 调试器实例

// @return

//是否删除成功哦你


BOOL
DbgRemoveHardwareBreakpoint(
							PDEBUGGEE dbg,
							ULONG Address,
							INT Number
							)
							/*++
							Remove hardward breakpoint
							--*/
{
	ULONG i;
	//ULONG j;
	BOOL a;
	REG_DR7 dr7;
	//	ThreadTableNode hThreadHead;

	CONTEXT ctx = {CONTEXT_ALL};

	if (Address)
	{
		Number = -1;
		for (i=0; i<MAX_BPS; i++)
		{
			if (dbg->bps[i].Present == 1 && dbg->bps[i].AddressLow == Address)
			{
				Number = i; 
				break;
			}
		}
	}

	if (Number != -1)
	{
		i = dbg->bps[Number].BpNum;

		dbg->bps[Number].Present = 0;
		dbg->hws[i] = NULL;



		//调用数据结构的回调函数进行处理
		List_map(dbg->ThreadHandleTable,ClearHardBreakPoint,&i);


		return TRUE;

	}

	//    lstrcpy (cdbg_last_err, "Not found");
	return FALSE;
}


BOOL
DbgRemoveMemoryBreakpoint(
						  PDEBUGGEE dbg,
						  ULONG Address,
						  INT Number
							 )
{
	
	ULONG i;
	//ULONG j;
	BOOL a;
	REG_DR7 dr7;
	
	//用来保存无用的内存信息
	DWORD dwOldProtect;

	//	ThreadTableNode hThreadHead;

	CONTEXT ctx = {CONTEXT_ALL};

	if (Address)
	{
		Number = -1;
		for (i=0; i<MAX_BPS; i++)
		{
			if ((dbg->bps[i].Present == 1) && 
				//需要判断地址是否命中
				((Address - dbg->bps[i].AddressLow) >= 0 && (Address - dbg->bps[i].AddressLow) < 4)&& 
				(dbg->bps[i].BreakType == BREAK_TYPE_MEMORY))
			{
				Number = i; 
				break;
			}
		}
	}

	if (Number != -1)
	{
		i = dbg->bps[Number].BpNum;

		dbg->bps[Number].Present = 0;
		dbg->mbps[i] = NULL;

		//更新内存信息,通过地址找到内存分页
		UpdateMemTable(dbg);
		List_map(dbg->MemTable,FindMemNodeMemory,&Address);
		//恢复页面属性
		VirtualProtectEx(dbg->hProcess,dbg->pCurrentMemNode->BaseAddress,
						dbg->pCurrentMemNode->RegionSize,dbg->bps[Number].OldPageProtect,
						&dwOldProtect);

		//VirtualProtectEx(dbg->hProcess,dbg->pCurrentMemNode->BaseAddress,
		//		dbg->pCurrentMemNode->RegionSize,0X20,
		//		&dwOldProtect);
		
		//继续执行
		return TRUE;
	}
	
	return FALSE;
}

INT
DbgSetMemoryBreakpoint(
					   PDEBUGGEE dbg,
					   ULONG Address,
					   BOOLEAN OneShot,
					   MEM_BREAK_TYPE Type,//读/写
					   UCHAR Length
					   )
{
	ULONG t;
	SIZE_T i;
	SIZE_T j;
	PUCHAR bpbase;
	PBREAKPOINT *ppBreakPoint;
	DWORD dwOldProtect;


	//1.找到空闲的内存断点指针

	for(j = 0; j < MAX_MEM_BREAKPOINT; j++)
	{
		if(dbg->mbps[j] == NULL)
		{
			break;
		}
	}

	//满了
	if(j == MAX_MEM_BREAKPOINT)
	{
		perror("Can't Set Memory Break,It's Full.");
		SETERROR("Can't Set Memory Break,It's Full.");
		return 0;
	}


	ppBreakPoint = &dbg->mbps[j];

	//2.找到空闲的断点信息表
	for (i=0; i<MAX_BPS; i++)
	{
		if (dbg->bps[i].Present == 0)
		{
			dbg->bps[i].Present = 1;
			dbg->bps[i].BreakType = BREAK_TYPE_MEMORY;
			dbg->bps[i].AddressLow = Address;

			dbg->bps[i].OneShot = OneShot;

			printf("MemoryBreakPoint in %X\n",Address);

			//mbps中的成员正确指向空闲的内存断点
			(*ppBreakPoint) = &dbg->bps[i];

			dbg->bps[i].BreakLen = Length;
			//对应的内存断点表位置
			dbg->bps[i].BpNum = j;
			dbg->bps[i].Protect = Type;


			if (OneShot)
			{
				UCHAR buffer[SIZEOF_BP_BUFFER];

				if ( !ReadProcessMemory (dbg->hProcess, (LPCVOID)Address, buffer, SIZEOF_BP_BUFFER, &t))
				{
					//					FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
					return -1;
				}

				//				buffer[0] = OldByte;

				//				len = size_of_code (buffer);
				bpbase = (PUCHAR) dbg->BreakPointBuffers;

				//				buffer[len] = 0xE9;
				//				*(ULONG*)&buffer[len+1] = (Address + len) - ((ULONG)bpbase + SIZEOF_BP_BUFFER*i + len) - 5;

				if ( !WriteProcessMemory (dbg->hProcess, bpbase + SIZEOF_BP_BUFFER*i, buffer, SIZEOF_BP_BUFFER, &t))
				{
					//					FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, cdbg_last_err, sizeof(cdbg_last_err)-1, 0);
					return -1;
				}

				dbg->bps[i].AddressOfBuffer = (ULONG)bpbase + SIZEOF_BP_BUFFER*i;
			}

			if(!VirtualProtectEx(dbg->hProcess,
				dbg->pCurrentMemNode->BaseAddress,
				dbg->pCurrentMemNode->RegionSize,
				PAGE_NOACCESS,
				&dwOldProtect))
			{
				perror("Set Protect error.");
				SETERROR("Set Protect error.");
				return -1;
			}

			//保存旧的内存分页信息
			dbg->bps[i].OldPageProtect = dwOldProtect;
			
			return 1;
		}
	}

	//lstrcpy (cdbg_last_err, "Not enough slots");
	return -1;
}


HANDLE
DbgLookupThread(
				PDEBUGGEE dbg,
				ULONG UniqueThread
				)
{
	return FALSE;
}

BOOL
DbgContinue(
			PDEBUGGEE dbg
			)
{
	if (!dbg->Stopped)
	{
		//lstrcpy (cdbg_last_err, "Debuggee is already running");
		SETERROR("Debuggee is already running");
		return FALSE;
	}

	DbgResumeProcess (dbg);
	dbg->Stopped = 0;
	return TRUE;
}

VOID
DbgSuspendProcess(
				  PDEBUGGEE dbg
				  )
{
}

VOID
DbgResumeProcess(
				 PDEBUGGEE dbg
				 )
{
	/*++
	Resumes all threads suspended by CdbgSuspendProcess()
	--*/
	//ULONG i;
	//
	////for (i=0; i<dbg->nThreads; i++)
	////{
	////		if (dbg->dwThreadIds[i] & 0x80000000)
	////		{
	////				dbg->dwThreadIds[i] &= ~0x80000000;
	////				ResumeThread (dbg->hThreads[i]);
	////		}
	////}
	//List_T p;
	//DWORD dwTmpId = 0;
	//List_T lstThreadHandleTable;

	//lstThreadHandleTable = dbg->ThreadHandleTable;

	//for(p = lstThreadHandleTable, i = 0; i  < (ULONG)List_length(p); i++,p = p->rest)
	//{
	//	if(((ThreadTableNode*)p->first)->dwThreadId & 0x80000000)
	//	{
	//		((ThreadTableNode*)p->first)->dwThreadId &= ~0x80000000;
	//		ResumeThread (((ThreadTableNode*)p->first)->hThread);
	//	}
	//}

	//1、结构体中增加一个成员，用来保存当前出错的地址
	//2、Remove这个断点
	//3、得到BreakContex中的EIP并减一
	//4、SetThreadContex到目标线程
	//5、ReleaseMutex

	//if (dbg->cur_bps->Hardware)

	//不同中断类型做不同处理
	switch(dbg->cur_bps->BreakType)
	{
	case BREAK_TYPE_HARDWARD:
		DbgRemoveHardwareBreakpoint(dbg,dbg->cur_bps->AddressLow,-1);		
		break;
	case BREAK_TYPE_MEMORY:

		break;
	case BREAK_TYPE_SOFT:
		DbgRemoveSoftwareBreakpoint(dbg,dbg->cur_bps->AddressLow,-1);
		SetThreadContext(dbg->hDebugThread,&dbg->BreakContext);		
		break;
	}
	//if (dbg->cur_bps->BreakType == BREAK_TYPE_HARDWARD)
	//{

	//}
	//else
	//{

	//}
}






//-------------------------朴素的分割线-----------------------------
//-------------------------下面是一些实现的辅助性质的函数----------

// 通过查找目标进程线程表中的数据，得到线程句柄
// name: FindThreadHandle
// @param
// dwThreadId: 目标线程ID
// hThread: 目标线程句柄
// @return
// 是否找到

BOOL FindThreadHandle(PDEBUGGEE dbg,IN DWORD dwThreadId,OUT PHANDLE hThread)
{
	int i = 0;
	List_T p;
	DWORD dwTmpId = 0;
	List_T lstThreadHandleTable;

	lstThreadHandleTable = dbg->ThreadHandleTable;

	for(p = lstThreadHandleTable; i  < List_length(p); i++,p = p->rest)
	{
		dwTmpId = ((ThreadTableNode*)p->first)->dwThreadId;
		if(dwThreadId ==  dwThreadId)
		{
			(*hThread) = ((ThreadTableNode*)p->first)->hThread;
			return TRUE;
		}
	}
	return FALSE;
}

void FindThreadHandleMember(void **x, void *cl)
{
	ThreadTableNode *ndSrc;
	ThreadTableNode *ndDst;

	ndDst = cl;
	ndSrc = (*x);

	if(ndSrc->dwThreadId == ndDst->dwThreadId)
	{
		ndDst->hThread = ndSrc->hThread;
	}
}

void RemoveThreadHandle(void **x, void *cl)
{
	ThreadTableNode *tn;
	tn = (*x);

	if(tn->dwThreadId == (UINT)(*(UINT*)cl))
	{
		tn->dwThreadId = 0;
		tn->hThread = NULL;
	}
}

void DestroyThreadHandle(void **x, void *cl)
{
	if(x)
	{
		free(*x);
	}
}

void FindMemNodeMemory(void **x,void *cl)
{
	//~ PMemNode nd;
	//~ nd = (*x);

	//~ 
	PMemNode nd;
	UINT addr;
	UINT addr2;
	UINT addr3;

	nd = (PMemNode)*x;

	addr = (UINT)(*((PUINT)cl));
	addr2 = (UINT)nd->BaseAddress;
	addr3 = nd->RegionSize;
	if((addr >= addr2) && (addr <addr2 + addr3))
	{
		//~ printf("%s\n","find");
		//~ printf("%p %d\n",nd->BaseAddress,nd->RegionSize);
		//~ ((UINT)*((UINT*)cl)) = (UINT)nd->BaseAddress;
		moDbg->pCurrentMemNode = nd;
	}
}


// 更新内存表信息内存

// name: UpdateMemTable

// dbg: moDebug实例

// @return 是否遍历成功

BOOL UpdateMemTable(PDEBUGGEE dbg)
{
	MEMORY_BASIC_INFORMATION mbi;
	BOOL fOk = TRUE;
	PVOID pvAddress = NULL;
	MemNode *nd = NULL;
	int i;
	HANDLE hProcess;

	i = 0;
	hProcess = dbg->hProcess;


	//销毁其中所有成员所分配的内存
	List_map(dbg->MemTable,DestroyThreadHandle,NULL);
	List_free(&dbg->MemTable);
	dbg->MemTable = NULL;


	while (fOk) 
	{

		fOk = VirtualQueryEx(hProcess,pvAddress,&mbi,sizeof(mbi));

		pvAddress =  (PBYTE)pvAddress + mbi.RegionSize;

		if (mbi.Type == 0 || mbi.State == MEM_RESERVE)
		{
			//不用保存
			continue;
		}
		i++;
		//保存
		nd = (MemNode*)malloc(sizeof(*nd));
		memset(nd,0,sizeof(*nd));
		nd->nID = i;                // 唯一标识
		nd->BaseAddress = mbi.BaseAddress;           // 分页开始基地址
		nd->AllocationBase = mbi.AllocationBase;        // 开始基址四舍五入后的结果
		nd->AllocationProtect = mbi.AllocationProtect;
		nd->RegionSize = mbi.RegionSize;
		nd->State = mbi.State;                 // 状态
		nd->Protect = mbi.Protect;               // 属性
		nd->newProtect = 0;//mbi.Protect;            // 新属性
		nd->Type = mbi.Type;


		dbg->MemTable = List_push(dbg->MemTable,nd);
		nd = NULL;
	}

	//printf("%d\n",i);


	//parg = &arg;

	//printf("%p\n",parg);
	//List_map(list,List_find_member,parg);

	//printf("%p\n",arg);

	//List_map(list,List_free_member,NULL);
	//List_free(&list);
	return TRUE;
}

void ClearHardBreakPoint(void **x, void *cl)
{ 
	ThreadTableNode *tn;
	ULONG i;
	REG_DR7 dr7;
	CONTEXT ctx = {CONTEXT_DEBUG_REGISTERS};
	BOOL a;

	tn = ((ThreadTableNode*)*x);
	a = GetThreadContext (tn->hThread, &ctx);

	if(!a)
	{
		__asm int 3
	}
	i = (ULONG)(*(ULONG*)cl);

	dr7.Raw = ctx.Dr7;

	switch (i)
	{
	case 0:
		dr7.Local0 = 0;
		ctx.Dr0 = 0;
		break;
	case 1:
		dr7.Local1 = 0;
		ctx.Dr1 = 0;
		break;
	case 2:
		dr7.Local2 = 0;
		ctx.Dr2 = 0;
		break;
	case 3:
		dr7.Local3 = 0;
		ctx.Dr3 = 0;
		break;
	}

	ctx.Dr7 = dr7.Raw;

	a = SetThreadContext (tn->hThread, &ctx);

	if(!a)
	{
		__asm int 3
	}
}


// 获取下一条指令的地址

// name: GetNextInstruct

// @param

// PDEBUGGEE dbg 调试器实例

// PULONG nextStruct 指向下一条指令的地址

// @return

// 无返回值

VOID GetNextInstructAddr(PDEBUGGEE dbg,PULONG nextStruct)
{
	ULONG addr;
	char buff[16];
	SIZE_T l = 0;
	INSTRUCTION inst;
	//保存原来CurrentMem的值
	LPVOID OldAddr;
	DWORD dwOldProtect;



	addr = dbg->BreakContext.Eip;
	//先保存当前地址的内存分页
	UpdateMemTable(dbg);
	List_map(dbg->MemTable,FindMemNodeMemory,&addr);
	
	//将其设为可执行
	VirtualProtectEx(dbg->hProcess,
		dbg->pCurrentMemNode->BaseAddress,
		dbg->pCurrentMemNode->RegionSize,PAGE_EXECUTE,&dwOldProtect);
	GetLastError();

	//得到吓一条数据段的地址
	ReadProcessMemory(dbg->hProcess,(LPVOID)(addr),buff,16,&l);
	l = get_instruction(&inst, buff, MODE_32);	
	(*nextStruct) = (dbg->BreakContext.Eip + l);
	//写回属性
	VirtualProtectEx(dbg->hProcess,dbg->pCurrentMemNode->BaseAddress,dbg->pCurrentMemNode->RegionSize,
					 dbg->pCurrentMemNode->Protect,&dwOldProtect);
					 	
}

//-----------------------------朴素的分割线------------------------------
//调试用到的消息表，主要是给调试线程调用0
// 调试信息.被调试进程启动时会触发
DWORD OnDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{
	ULONG address;
	HANDLE hThread;
	HANDLE hThread2;
	ThreadTableNode nd;
	ULONG nextStruct = 0;
	PMemNode pm;
	DWORD dwOldProtect;

	SIZE_T i;

	address = (ULONG)dbgEvent->u.Exception.ExceptionRecord.ExceptionAddress;

	dbg->Stopped = 1;

	nd.dwThreadId = dbgEvent->dwThreadId;
	nd.hThread = NULL;
	List_map(dbg->ThreadHandleTable,FindThreadHandleMember,&nd);

	if(!nd.hThread)
	{
		__asm int 3
	}

	hThread = nd.hThread;

	dbg->hDebugThread = nd.hThread;

	//hThread2 = OpenThread(TRUE,FALSE,dbgEvent->dwThreadId);

	dbg->BreakContext.ContextFlags = CONTEXT_ALL ;


	if (GetThreadContext(hThread,&dbg->BreakContext) == 0)
	{
		__asm int 3
	}

	switch (dbgEvent->u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:
		if(dbg->IsForMemBreak)
		{
			//将断点分页接着设成不可访问.
			 DbgRemoveSoftwareBreakpoint(dbg,address,-1);

			 dbg->BreakContext.Eip = dbg->BreakContext.Eip - 1;

			 SetThreadContext(hThread,&dbg->BreakContext);


				if(!VirtualProtectEx(dbg->hProcess,
					dbg->pCurrentMemNode->BaseAddress,
					dbg->pCurrentMemNode->RegionSize,
					PAGE_NOACCESS,
					&dwOldProtect))
			 {
				 perror("Set Protect error.");
				 SETERROR("Set Protect error.");
				 return -1;
			 }
				//DbgSetMemoryBreakpoint(

			 dbg->IsForMemBreak = FALSE;
		}
		else if(DbgLookupUserBreakPoint(dbg,address))
		{
			printf("%s %p\r\n","user breakpoint",address);
			GetNextInstructAddr(dbg,&nextStruct);
			printf("next struction %p:\n",nextStruct);
	
			Sleep(1000);

			//挂起调试线程，等待接收用户输入
			SuspendThread(dbg->hTheDebuggerThread);		
		}
		goto LABLE_DBG_CONTINUE;

	case EXCEPTION_SINGLE_STEP:
		printf("%s %p\r\n","breakpoint address:",address);

		if(DbgLookupUserBreakPoint(dbg,address))
		{
			printf("%s\r\n","user breakpoint");
		}
		GetNextInstructAddr(dbg,&nextStruct);

		printf("next struction %p:\n",nextStruct);

		Sleep(1000);

		//挂起调试线程，等待接收用户输入
		SuspendThread(dbg->hTheDebuggerThread);			

		//		RemoveHardwareBreakpoint(0x01012475,-1);
		goto LABLE_DBG_CONTINUE;
	case EXCEPTION_ACCESS_VIOLATION:
		//判断能不能在内存断点信息表中找到符合该断点的分页
		//dbg->pCurrentMemNode指向对对应的内存分页信息表成员

		UpdateMemTable(dbg);

		for(i = 0,dbg->pCurrentMemNode = NULL;
			dbg->mbps[i] != NULL; 
			i++)
		{
			dbg->pCurrentMemNode = NULL;
			List_map(dbg->MemTable,FindMemNodeMemory,&address);
			if(dbg->pCurrentMemNode != NULL)
			{
				break;
			} //found
		}

		//在内存断点中找到了当前页面
		if(dbg->pCurrentMemNode != NULL)
		{
			
			//当前断点与内存断点表中的断点是否命中,匹配则提示用户并恢复.
			if((dbg->mbps[i]->AddressLow == address) ||
			    (((address - dbg->mbps[i]->AddressLow) >= 0) && 
				((address - dbg->mbps[i]->AddressLow) < dbg->mbps[i]->BreakLen)))
			{
				printf("The memory break point at %p is comming.\n",address);
				
				DbgRemoveMemoryBreakpoint(dbg,address,-1);		
				__asm int 3   			
			}
			
			//是为了内存断点才断下的,再设置这个属性
			else
			
			{
				//不匹配则获取下一条指令的地址
				//并设置其软中断并修改dbg->IsForMemBreak为True
				//这里还需要将触发断点的内存分页设置为可读可写可执行
				

				
				//这个函数会修改pCurrentMemNode的值
				GetNextInstructAddr(dbg,&nextStruct);
				if(!VirtualProtectEx(dbg->hProcess,
					dbg->pCurrentMemNode->BaseAddress,
					dbg->pCurrentMemNode->RegionSize,
					//PAGE_EXECUTE_READ,
					dbg->mbps[i]->OldPageProtect,
					&dwOldProtect))
				{
					perror("write memory error.");
					SETERROR("write memory error.");
					goto LABLE_DBG_CONTINUE;
				}
				
				DbgSetSoftwareBreakpoint(dbg,nextStruct,TRUE);
				
				//恢复工作应该在dbg->IsForMemBreak判断成功时进行
				
				dbg->IsForMemBreak = TRUE;
			}
		}

 		__asm int 3
		goto LABLE_DBG_CONTINUE;
	case 0x4000001f:
	case 0x4000001e:
		goto LABLE_DBG_CONTINUE;
	}

	goto LABLE_DBG_CONTINUE;


LABLE_DBG_CONTINUE:
	dbg->Stopped = 0;
	return DBG_CONTINUE;

LABLE_DBG_NOTEHANDLED:
	dbg->StoppedContext = 0;
	dbg->Stopped = 0;
	return DBG_CONTINUE;
}

// 被调试进程创建线程时时触发
DWORD OnCreateThreadEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{
	ThreadTableNode *nd = NULL;

	//将节点添加进链表
	nd = (ThreadTableNode*)malloc(sizeof(ThreadTableNode));

	memset(nd,0,sizeof(*nd));

	nd->dwThreadId = dbgEvent->dwThreadId;
	nd->hThread = dbgEvent->u.CreateThread.hThread;

	dbg->ThreadHandleTable = 
		List_push(dbg->ThreadHandleTable,nd);
	return DBG_CONTINUE;
}

// 被调试进程被创建时触发
DWORD OnCreateProcessDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{
	CONTEXT ctx = {CONTEXT_DEBUG_REGISTERS};
	ThreadTableNode *nd = NULL;

	union REG_DR7 dr7;

	MEMORY_BASIC_INFORMATION mbi;
	moDbg->hProcess = dbgEvent->u.CreateProcessInfo.hProcess;
	wprintf(L"%s%d\n",L"\tCreateProcessEvent PID=" , dbgEvent->dwProcessId);

	// 保存创建线程时的进程信息.
	nd = (ThreadTableNode*)malloc(sizeof(ThreadTableNode));
	nd->dwThreadId = dbgEvent->dwThreadId;
	nd->hThread = dbgEvent->u.CreateProcessInfo.hThread;

	dbg->ThreadHandleTable = List_push(dbg->ThreadHandleTable,nd);

	DbgSetSoftwareBreakpoint(moDbg,(ULONG)dbgEvent->u.CreateProcessInfo.lpStartAddress,FALSE);
	//DbgSetHardwareBreakpoint(moDbg,(ULONG)dbgEvent->u.CreateProcessInfo.lpStartAddress,FALSE,0,1);
	//	__asm int 3

	return DBG_CONTINUE;
}

// 被调试线程退出时触发
// name: OnExitThreadDebugEvent
// @param
// 需处理u.ExitThread
// @return是否执行成功
DWORD OnExitThreadDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{
	//typedef struct _EXIT_THREAD_DEBUG_INFO {
	//    DWORD dwExitCode;
	//} EXIT_THREAD_DEBUG_INFO, *LPEXIT_THREAD_DEBUG_INFO;
	PUINT pThreadId;
	printf("%s%d%s%d\n" ,"\tExitThreadEvent TID=" , dbgEvent->dwThreadId , " ExitCode=" ,
		dbgEvent->u.ExitThread.dwExitCode);

	pThreadId = &dbgEvent->dwThreadId;
	List_map(dbg->ThreadHandleTable,RemoveThreadHandle,pThreadId);

	return DBG_CONTINUE;
}

// 被调试进程退出时触发
DWORD OnExitProcessDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{	
	//DbgClear(dbg);
	return DBG_CONTINUE;
}

// 被调试进程加载DLL时触发
DWORD OnLoadDllDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{
	//需要维护一个表,在DLL装载的时候遍历DLL，获得其中的地址，在反汇编时进行比对
	return DBG_CONTINUE;
}

// 被调试进程卸载DLL时触发
DWORD OnUnLoadDllDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{
	return DBG_CONTINUE;
}

// 被调试进程输出调试信息时触发
DWORD OnOutputDebugStringEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{
	return DBG_CONTINUE;
}

// 当被调试进程出错时触发.
DWORD OnRipEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg)
{	
	return DBG_CONTINUE;

}

//----------------------------朴素的分割线-------------------------------

void OutputCreateProcessEvent ( DEBUG_EVENT *dbgEvent, FILE *f)
{
	CREATE_PROCESS_DEBUG_INFO * stCPDI;
	stCPDI = &dbgEvent->u.CreateProcessInfo;
	printf ( "Create Process Event      :\n" ) ;
	printf ( "   hFile                  : 0x%08X\n" ,
		(*stCPDI).hFile                            ) ;
	printf ( "   hProcess               : 0x%08X\n" ,
		(*stCPDI).hProcess                         ) ;
	printf ( "   hThread                : 0x%08X\n" ,
		(*stCPDI).hThread                          ) ;
	printf ( "   lpBaseOfImage          : 0x%08X\n" ,
		(*stCPDI).lpBaseOfImage                    ) ;
	printf ( "   dwDebugInfoFileOffset  : 0x%08X\n" ,
		(*stCPDI).dwDebugInfoFileOffset            ) ;
	printf ( "   nDebugInfoSize         : 0x%08X\n" ,
		(*stCPDI).nDebugInfoSize                   ) ;
	printf ( "   lpThreadLocalBase      : 0x%08X\n" ,
		(*stCPDI).lpThreadLocalBase                ) ;
	printf ( "   lpStartAddress         : 0x%08X\n" ,
		(*stCPDI).lpStartAddress                   ) ;
	printf ( "   lpImageName            : 0x%08X\n" ,
		(*stCPDI).lpImageName                      ) ;
	printf ( "   fUnicode               : 0x%08X\n" ,
		(*stCPDI).fUnicode                         ) ;
}

void OutputCreateThreadEvent ( DEBUG_EVENT *dbgEvent, FILE *f)
{
	CREATE_THREAD_DEBUG_INFO * stCTDI;
	stCTDI = &dbgEvent->u.CreateThread;
	printf ( "Create Thread Event       :\n" ) ;
	printf ( "   hThread                : 0x%08X\n" ,
		(*stCTDI).hThread                          ) ;
	printf ( "   lpThreadLocalBase      : 0x%08X\n" ,
		(*stCTDI).lpThreadLocalBase                ) ;
	printf ( "   lpStartAddress         : 0x%08X\n" ,
		(*stCTDI).lpStartAddress                   ) ;
}

void OutputExitThreadEvent ( DEBUG_EVENT *dbgEvent, FILE *f)
{
	EXIT_THREAD_DEBUG_INFO * stETDI;
	stETDI = &dbgEvent->u.ExitThread;
	printf ( "Exit Thread Event         :\n" ) ;
	printf ( "   dwExitCode             : 0x%08X\n" ,
		(*stETDI).dwExitCode                       ) ;
}

void OutputExitProcessEvent ( DEBUG_EVENT *dbgEvent, FILE *f)
{
	EXIT_PROCESS_DEBUG_INFO * stEPDI;
	stEPDI = &dbgEvent->u.ExitProcess;
	printf ( "Exit Process Event        :\n" ) ;
	printf ( "   dwExitCode             : 0x%08X\n" ,
		(*stEPDI).dwExitCode                       ) ;
}

void OutputDllLoadEvent ( DEBUG_EVENT *dbgEvent, FILE *f)
{
	LOAD_DLL_DEBUG_INFO * stLDDI;
	stLDDI = &dbgEvent->u.LoadDll;
	printf ( "DLL Load Event            :\n" ) ;
	printf ( "   hFile                  : 0x%08X\n" ,
		(*stLDDI).hFile                            ) ;
	printf ( "   lpBaseOfDll            : 0x%08X\n" ,
		(*stLDDI).lpBaseOfDll                      ) ;
	printf ( "   dwDebugInfoFileOffset  : 0x%08X\n" ,
		(*stLDDI).dwDebugInfoFileOffset            ) ;
	printf ( "   nDebugInfoSize         : 0x%08X\n" ,
		(*stLDDI).nDebugInfoSize                   ) ;
	printf ( "   lpImageName            : 0x%08X\n" ,
		(*stLDDI).lpImageName                      ) ;
	printf ( "   fUnicode               : 0x%08X\n" ,
		(*stLDDI).fUnicode                         ) ;
}

void OutputDllUnLoadEvent ( DEBUG_EVENT *dbgEvent, FILE *f)
{
	UNLOAD_DLL_DEBUG_INFO * stULDDI;
	stULDDI = &dbgEvent->u.UnloadDll;
	printf ( "DLL Unload Event          :\n" ) ;
	printf ( "   lpBaseOfDll            : 0x%08X\n" ,
		(*stULDDI).lpBaseOfDll                     ) ;
}

void OutputExceptionEvent ( DEBUG_EVENT *dbgEvent, FILE *f)
{
	EXCEPTION_DEBUG_INFO * stEDI;
	stEDI = &dbgEvent->u.Exception;
	printf ( "Exception Event           :\n" ) ;
	printf ( "   dwFirstChance          : 0x%08X\n" ,
		(*stEDI).dwFirstChance                     ) ;
	printf ( "   ExceptionCode          : 0x%08X\n" ,
		(*stEDI).ExceptionRecord.ExceptionCode     ) ;
	printf ( "   ExceptionFlags         : 0x%08X\n" ,
		(*stEDI).ExceptionRecord.ExceptionFlags    ) ;
	printf ( "   ExceptionRecord        : 0x%08X\n" ,
		(*stEDI).ExceptionRecord.ExceptionRecord   ) ;
	printf ( "   ExceptionAddress       : 0x%08X\n" ,
		(*stEDI).ExceptionRecord.ExceptionAddress  ) ;
	printf ( "   NumberParameters       : 0x%08X\n" ,
		(*stEDI).ExceptionRecord.NumberParameters  ) ;
}
