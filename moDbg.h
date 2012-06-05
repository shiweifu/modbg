#ifndef __MODBG_H__
#define __MODBG_H__

#include "global_header.h"

#define __MODBG_VER "moDbg 0.1"
#define ERR_LEN 256
#define NAME_LEN 256
#define COMMAND_TABLE_LEN 1024

#define SETERROR(s) memset(err,0,256);\
	strcpy(err,s)

#define MAX_MEM_BREAKPOINT 16


// msg handler
#define CMD_ENTRY(NAME,ARGC,HELP) { do_##NAME, ARGC, #NAME, HELP }
#define CMD_END {0,0,0}
#define CMDHANDLER(CMD) void do_##CMD(int argc, char** argv)

#define DO_COMMAND(CMD) do_##CMD(argc,argv);
#define DO_COMMAND_NOARG(CMD) do_##CMD(0,NULL);


struct DEBUGGEE;
struct _MemNode;
typedef struct _MemNode MemNode;
typedef struct DEBUGGEE DEBUGGEE; 


extern char err[ERR_LEN];
typedef struct CMD_HANDLER_ENTRY CMD_HANDLER_ENTRY;


struct CMD_HANDLER_ENTRY
{
	void (*handler)(int,char**);
	int args;
	char *name;
	char *help;
};

extern CMD_HANDLER_ENTRY CommandTable[COMMAND_TABLE_LEN];

//实现的功能
CMDHANDLER (open);
CMDHANDLER (debug );
CMDHANDLER (disasm);
CMDHANDLER (close);
CMDHANDLER (go);
CMDHANDLER (step);
CMDHANDLER (bp);
CMDHANDLER (hbp);
CMDHANDLER (mbp);
CMDHANDLER (exit);
CMDHANDLER (help);
CMDHANDLER (now);
CMDHANDLER (attach);
CMDHANDLER (dm);
CMDHANDLER (ver);
CMDHANDLER (tasklist);
CMDHANDLER (process);
CMDHANDLER (thread);
CMDHANDLER (taskkill);


//参数
#define hinit() heap = GetProcessHeap();

#define halloc(x) HeapAlloc(heap, HEAP_ZERO_MEMORY, x)
#define hfree(x) HeapFree(heap,0,x)
#define GetArg(x) __getarg(argc,argv,x)
#define FreeArg(p) free(p)


typedef enum ARG_TYPE
{
	AT_DWORD,
	AT_STRING
} ARG_TYPE;

typedef enum MEM_BREAK_TYPE
{
	MEM_READ,
	MEM_WRITE
} MEM_BREAK_TYPE;

//
// Get command argument from argv[] array, recognize its type and fill ARG structure
//

typedef struct ARG
{
	ARG_TYPE type;
	union
	{
		ULONG dw;
		char str[256];
	};
} ARG;

ARG* __getarg (int argc, char** argv, int n);


//实现硬件断点的定义

typedef struct ThreadTableNode ThreadTableNode;
#define SIZEOF_BP_BUFFER 32

#define EFLAGS_TF  (1<<8)

struct ThreadTableNode
{
	DWORD dwThreadId;
	HANDLE hThread;
};

typedef union REG_DR7
{
        struct
        {
                ULONG Local0 : 1;
                ULONG Global0 : 1;
                ULONG Local1 : 1;
                ULONG Global1 : 1;
                ULONG Local2 : 1;
                ULONG Global2 : 1;
                ULONG Local3 : 1;
                ULONG Global3 : 1;
                ULONG LocalE : 1;
                ULONG GlobalE : 1;

                ULONG Reserved : 6;

                ULONG ReadWrite0 : 2;
                ULONG Len0 : 2;
                ULONG ReadWrite1 : 2;
                ULONG Len1: 2;
                ULONG ReadWrite2 : 2;
                ULONG Len2 : 2;
                ULONG ReadWrite3 : 2;
                ULONG Len3 : 2;
        };
        ULONG Raw;
}REG_DR7, *PREG_DR7;

//STATIC_ASSERT (sizeof(REG_DR7) == sizeof(ULONG));

typedef union REG_DR6
{
        struct
        {
                ULONG Break0 : 1;
                ULONG Break1 : 1;
                ULONG Break2 : 1;
                ULONG Break3 : 1;
                ULONG Reserved : 9;
                ULONG BD : 1;
                ULONG BS : 1;
                ULONG BT : 1;
                ULONG Reserved2 : 12;
        };
        ULONG Raw;
} *PREG_DR6;

//跟调试器相关的数据结构
#define MAX_BPS 128
//
// Breakpoints
//

typedef enum BREAK_TYPE
{
	BREAK_TYPE_HARDWARD,
	BREAK_TYPE_MEMORY,
	BREAK_TYPE_SOFT
} BREAK_TYPE;


typedef struct BREAKPOINT
{
	union
	{
			ULONG Address;
			struct
			{
					ULONG AddressLow : 31;
					ULONG Present : 1;
			};
	};
//	BOOLEAN Hardware;
	
	BREAK_TYPE BreakType;
	BOOLEAN OneShot;
	BOOLEAN Disabled;
	union
	{
			UCHAR OldByte;  // if Hardware == 0 && OneShot == 1
			struct
			{
					UCHAR Type;             // if Hardware == 1
					UCHAR BpNum;
			};
			ULONG AddressOfBuffer; // if Hardware == 0 && OneShot == 0
	};

	// 内存断点结构体,仅当Type是内存的情况下下面两个成员才有效
	SIZE_T          BreakLen    ;    // 内存断点的长度
	DWORD           Protect     ;    // 权限(1:读 2:写)
	DWORD           OldPageProtect     ;    // 这个内存信息表的分页属性

}  BREAKPOINT,*PBREAKPOINT;

typedef struct DEBUGGEE
{
        BOOLEAN Stopped;
        BOOLEAN StoppedSystem;
        ULONG StoppedContext;

		CONTEXT BreakContext;

        BOOLEAN SingleStepNext;
        ULONG StoppedEip;

		//目标进程的句柄和ID
        HANDLE hProcess;
        ULONG dwProcessId;

		//当前被调试线程的ID
		ULONG dwDebugThreadId;
		//当前被调试线程的句柄
		HANDLE hDebugThread;

		HANDLE hTheDebuggerThread;

		HANDLE hMutex;
        
        //保存线程和线程ID的表
		//~ ULONG nThreads;
		//~ HANDLE *hThreads;
        //~ ULONG *dwThreadIds;
        //~ 
		List_T ThreadHandleTable;
		//用于保存内存信息
		List_T MemTable;


        char name[256];
        ULONG ModuleBase;
        ULONG EntryPoint;

		//判断是否因为是内存断点才中断的，如果是要恢复
		BOOL IsForMemBreak;
		SIZE_T IndexMemoryBreaks;


        PVOID hooks;
        PVOID BreakPointBuffers;

		//软件断点表
        BREAKPOINT bps[MAX_BPS];
		//当被调试程序中断的时候，用来判断是否在断点表中，如果在，则指向
		BREAKPOINT *cur_bps;
		//硬件断点表
        PBREAKPOINT hws[4];
        
		//内存断点表
		PBREAKPOINT mbps[MAX_MEM_BREAKPOINT];

        //保存当前将操作的内存信息
        MemNode *pCurrentMemNode;
} *PDEBUGGEE;

extern PDEBUGGEE moDbg; 


//干活的函数

//调试线程
DWORD WINAPI DebugThreadProc(
						LPVOID lpParameter
						);

VOID
DbgCorrectPatchedMemory(
						PDEBUGGEE dbg,
						ULONG VirtualAddressStart,
						ULONG Size,
						PVOID Buffer
						);
PDEBUGGEE
DbgOpen(
		  char *name
		  );

PDEBUGGEE
DbgAttach(
		  ULONG dwProcessId
		  );

//查找断点是否是调试器用户下的
BOOL
DbgLookupUserBreakPoint(
						 PDEBUGGEE dbg,
						 ULONG Address);

VOID
DbgDetach(
		  PDEBUGGEE dbg
		  );

VOID
DbgFastDetach(
			  PDEBUGGEE dbg
			  );

BOOL
DbgLookupProcessName(
					 //PSYSTEM_PROCESSES_INFORMATION Buffer OPTIONAL,
					 ULONG dwProcessId,
					 char *ProcessNameBuffer,
					 ULONG MaxLength
					 );

BOOL
DbgUserExceptionDispatcherHook(
							   PDEBUGGEE dbg
							   );

VOID
DbgUserExceptionDispatcherUnhook(
								 PDEBUGGEE dbg
								 );
								 

ULONG
WINAPI
DbgLpcServer(
			 LPVOID pdbg
			 );

INT
DbgSetSoftwareBreakpoint(
						 PDEBUGGEE dbg,
						 ULONG Address,
						 BOOLEAN OneShot
						 );

BOOL
DbgRemoveHardwareBreakpoint(
							 PDEBUGGEE dbg,
							 ULONG Address,
							 INT Number
							 );

INT
DbgSetHardwareBreakpoint(
						 PDEBUGGEE dbg,
						 ULONG Address,
						 BOOLEAN OneShot,
						 UCHAR Type,
						 UCHAR Length
						 );
						 
BOOL
DbgRemoveMemoryBreakpoint(
							 PDEBUGGEE dbg,
							 ULONG Address,
							 INT Number
							 );

INT
DbgSetMemoryBreakpoint(
						 PDEBUGGEE dbg,
						 ULONG Address,
						 BOOLEAN OneShot,
						 MEM_BREAK_TYPE Type,//断点类型:读/写
						 UCHAR Length
						 );

BOOL
DbgRemoveSoftwareBreakpoint(
							PDEBUGGEE dbg,
							ULONG Address,
							INT Number
							);

BOOL
DbgDisableSoftwareBreakpoint(
							 PDEBUGGEE dbg,
							 ULONG Address,
							 INT Number
							 );

BOOL
DbgEnableSoftwareBreakpoint(
							PDEBUGGEE dbg,
							ULONG Address,
							INT Number
							);

HANDLE
DbgLookupThread(
				PDEBUGGEE dbg,
				ULONG UniqueThread
				);

BOOL
DbgContinue(
			PDEBUGGEE dbg
			);

VOID
DbgClear(
			PDEBUGGEE dbg
			);

VOID
DbgSuspendProcess(
				  PDEBUGGEE dbg
				  );

VOID
DbgResumeProcess(
				 PDEBUGGEE dbg
				 );
				 
				 
VOID
DbgDisasm(					
     		 PDEBUGGEE dbg,
			 ULONG Address,
			 INT Count
			 );


//----------------------------朴素的分割线-------------------------------

#define __DISPLAY__
//#define OUTPUT_DEBUGEVENT_INFO(i,dst) 

//事件消息对照表
typedef struct EventMsg EventMsg;

typedef DWORD (*ProcessTheEvent)(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
typedef void (*OutputTheEvent) ( void * stCPDI, FILE *f) ; 

DWORD ProcessEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// 调试信息.被调试进程启动时会触发
DWORD OnDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// 被调试进程创建线程时时触发
DWORD OnCreateThreadEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// 被调试进程被创建时触发
DWORD OnCreateProcessDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// 被调试线程退出时触发
DWORD OnExitThreadDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// 被调试进程退出时触发
DWORD OnExitProcessDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// 被调试进程加载DLL时触发
DWORD OnLoadDllDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// 被调试进程卸载DLL时触发
DWORD OnUnLoadDllDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// 被调试进程输出调试信息时触发
DWORD OnOutputDebugStringEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// 当被调试进程出错时触发.
DWORD OnRipEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
 

struct EventMsg
{
	DWORD dwEventId;
	ProcessTheEvent PeFun;
	OutputTheEvent Ote;
};

extern EventMsg EventFuncs[];

//----------------------------朴素的分割线-------------------------------
//下面是输出调试信息的函数
// 这系列函数通过传进去相应结构体指针,输出到屏幕上相关结构体信息
void OutputCreateProcessEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputCreateThreadEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputExitThreadEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputExitProcessEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputDllLoadEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputDllUnLoadEvent ( DEBUG_EVENT *dbgEvent, FILE *f);
void OutputExceptionEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputODSEvent ( HANDLE hProcess ,
                       OUTPUT_DEBUG_STRING_INFO * stODSI    ) ;
 
 
 
//--------------------------朴素的分割线--------------------------------
//下面是用于实现内存断点所用到的数据结构
//三张表:
//内存信息表
//
typedef struct _MemNode
{
	int             nID    ;                // 唯一标识,这个标识同样是指向moDbg中调试断点的下标
	PVOID           BaseAddress ;           // 分页开始基地址
	PVOID           AllocationBase ;        // 开始基址四舍五入后的结果
	DWORD           AllocationProtect ;
	SIZE_T          RegionSize ;
	DWORD           State ;                 // 状态
	DWORD           Protect ;               // 属性
	DWORD           newProtect ;            // 新属性
	DWORD           Type ;
} MemNode, *PMemNode;

//更新内存分页信息
BOOL UpdateMemTable(PDEBUGGEE dbg);

//获取下一条指令的地址
VOID GetNextInstructAddr(PDEBUGGEE dbg,PULONG nextStruct);

//用于链表操作的回调函数
void ClearHardBreakPoint(void **x, void *cl);
void FindThreadHandleMember(void **x, void *cl);
void DestroyThreadHandle(void **x, void *cl);
void FindMemNodeMemory(void **x,void *cl);
#endif
