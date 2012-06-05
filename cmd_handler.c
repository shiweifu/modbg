#include <stdio.h>
#include "moDbg.h"

CMDHANDLER (open)
{
	HANDLE hThread;
	ARG *proc;// = GetArg(1);
	char name[32] = "";

	if (argc < 2)
	{
		DO_COMMAND(help);
		return;
	}
	proc = GetArg(1);


	if (moDbg)
	{
		printf("Already opened to %d [%s]\n", moDbg->dwProcessId, moDbg->name);
		return;
	}

	if (proc->type == AT_STRING)
	{
		//moDbg->name
//		moDbg = DbgOpen(proc->str);
		strcpy(name,proc->str);
		hThread = CreateThread(NULL,0,DebugThreadProc,proc->str,0,0);
		WaitForSingleObject(hThread,500);
	}
	if (moDbg == NULL)
	{
		printf("error in open %s\n",err);
		return;
	}
	
	moDbg->hTheDebuggerThread = hThread;

	FreeArg (proc);
}

CMDHANDLER (debug )
{
	printf("%s\n","debug");

}

CMDHANDLER (disasm)
{
	ARG *arg = NULL;
	//从哪开始反汇编
	ULONG addr;
	//要反汇编多少条语句
	size_t count;

	printf("user input: %s\n","disasm");	
	//判断是否初始化
	if (moDbg == NULL || moDbg->dwProcessId == 0)
	{
		return;
	}
	
	arg = GetArg(1);
	
	if((arg == NULL) || (arg->type == AT_STRING))
	{
		goto NOARG;
	}
	
	addr = arg->dw;
	
	arg = GetArg(2);
	
	if((arg == NULL) || (arg->type == AT_STRING))
	{
		goto ONEARG;
	}
	count = arg->dw;
	
	goto TWOARG;
	
//没有参数,反汇编当前EIP中地址,向下20条
NOARG:
	DbgDisasm(moDbg,0,0);
	return;
	
ONEARG:
	DbgDisasm(moDbg,addr,0);
	return;

TWOARG:
	DbgDisasm(moDbg,addr,count);
	return;
}

CMDHANDLER (close)
{
	printf("%s\n","close");

}


CMDHANDLER (go)
{

	//这里需要
	if (moDbg == NULL || moDbg->dwProcessId == 0)
	{
		return;
	}

	//拿到互斥
	
	WaitForSingleObject(moDbg->hMutex,INFINITE);

	if(!DbgContinue (moDbg))
			printf("Continue failed: %s\n", err);
	else
			printf("Continued.\n");
	//释放互斥
    ReleaseMutex(moDbg->hMutex);

	ResumeThread(moDbg->hTheDebuggerThread);

	//Sleep(500);
	//fputc('\r',stdin);

}
CMDHANDLER (bp)
{
	printf("%s\n","break");

}
CMDHANDLER (hbp)
{
	printf("%s\n","hbreak");

}

CMDHANDLER (mbp)
{
	ARG *arg;
	UINT addr;
	UINT len;
	MEM_BREAK_TYPE memType;
	printf("%s\n","mbreak");
	arg = GetArg(1);

	//判断参数是否正确
	if(arg == NULL || arg->type != AT_DWORD)
	{
		perror("memory break arg error");
		return;
	}
	addr = arg->dw;

	FreeArg(arg);
	
	arg = GetArg(2);
	//判断参数是否正确
	if(arg->type != AT_DWORD)
	{
		perror("memory break arg error");
		return;
	}
	
	if(arg == NULL)
	{	
		perror("memory break arg error");
		return;
	}
	len = arg->dw;	
	FreeArg(arg);
	
	
	//得到内存读写类型 1为读 2为写
	arg = GetArg(3);

	//判断参数是否正确
	if(arg->type != AT_DWORD)
	{
		perror("memory break arg error");
		return;
	}
	
	if(arg == NULL)
	{	
		perror("memory break arg error");
		return;
	}
	
	memType = arg->dw;
	FreeArg(arg);
	
	UpdateMemTable(moDbg);

	moDbg->pCurrentMemNode = NULL;

	List_map(moDbg->MemTable,FindMemNodeMemory,&addr);

	if(moDbg->pCurrentMemNode == NULL)
	{
		perror("not found the memory in memory pages");
	}

	//在这之前内存信息表已经更新完毕
	DbgSetMemoryBreakpoint(moDbg,addr,FALSE,memType,len);
}
CMDHANDLER (exit)
{
	printf("%s\n","exit");
	DbgClear(moDbg);

}
CMDHANDLER (help)
{
	int i;
	ARG *arg;
	
	struct 
	{
		char *name;//[NAME_LEN];
		char *help_arg;//[NAME_LEN];
	} help_table[] = 
	{
		{"open", "open [arg] \narg is the PE file path.\n"},
		{"debug", "debug : start debug,the execute must was opened"},
		{"disasm", "disasm : open a file by path"},
		{"close", "close : close the debugging file"},
		{"go", "go : run to break"},
		{"bp", "bp : break at address"},
		{"hbp", "hbp : hard break at address"},
		{"mbp", "mbp : memory break at address"},
		{"dm", "dm : display memory contents"},
		{"step", "step : step into one command"},

		{"exit", "exit : exit debugger"},
		{"help", "help"},
		{"attach", "attach : attach the process"},
		{"now", "now : display current debugger state"},
		{"ver"," ver : displays version information"},

		{"tasklist","tasklist : displays list of the processes in the system"},
		{"process", "process : earches the process by its name or PID"},
		{"thread", "thread : seacrhes the thread by its name or TID"},
		{"taskkill", "taskkill : kills the process by its PID"},		
		{0,0}
	};


	printf("%s\n","help");
	if(argc == 1)
	{
		arg = GetArg(0);
	} //if argc == 1
	
	if(argc == 2)
	{
		arg = GetArg(1);		
	} // if argc == 2
	
	printf("%s\n","usage:");
		
	
	for(i = 0; 
		help_table[i].name != NULL;
		i++)
	{
		if(strcmp(help_table[i].name,arg->str) == 0)
		{
			printf("%s\n",help_table[i].help_arg);
			return;
		}
	}
	
	DO_COMMAND_NOARG(ver);

	for (i = 0; CommandTable[i].name != NULL; i++)
	{
		printf("%s\n",CommandTable[i].help);
	}
	puts("");
	fflush(stdin);
	fflush(stdout);

}

CMDHANDLER (now)
{
	printf("%s\n","now");
	
}


CMDHANDLER (attach)
{

}

CMDHANDLER (dm)
{
}

CMDHANDLER (ver)
{
	puts("ver");
	printf("%s\n",__MODBG_VER);
}

CMDHANDLER (tasklist)
{
}

CMDHANDLER (process)
{
}

CMDHANDLER (thread)
{
}

CMDHANDLER (taskkill)
{
}

CMDHANDLER (step)
{
	//ULONG t;
//	CONTEXT ctx;

	ARG *arg;
	BOOL IsStepInto = FALSE;
	ULONG nextAddr = 0;

	if (moDbg->Stopped == 0)
	{
			printf("Debuggee is running.\n");
			return;
	}
    
    //判断是step还是step into
    if(argv[1] != NULL)
    {
		arg = GetArg(1);
    
		if(arg->type == AT_STRING)
		{
			if(strcmp(arg->str,"into") == 0)
			{
				IsStepInto == TRUE;
			}
		}
    }
	
	if(IsStepInto)
	{
		moDbg->BreakContext.EFlags |= EFLAGS_TF;

		SetThreadContext(moDbg->hDebugThread,&moDbg->BreakContext);
		moDbg->SingleStepNext = 1;
	}
	else
	{
		GetNextInstructAddr(moDbg,&nextAddr);
		DbgSetSoftwareBreakpoint(moDbg,nextAddr,TRUE);
		moDbg->BreakContext.EFlags ^= EFLAGS_TF;
	}

	FreeArg(arg);
	
	DO_COMMAND_NOARG (go);
}
