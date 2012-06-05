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

//ʵ�ֵĹ���
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


//����
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


//ʵ��Ӳ���ϵ�Ķ���

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

//����������ص����ݽṹ
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

	// �ڴ�ϵ�ṹ��,����Type���ڴ�����������������Ա����Ч
	SIZE_T          BreakLen    ;    // �ڴ�ϵ�ĳ���
	DWORD           Protect     ;    // Ȩ��(1:�� 2:д)
	DWORD           OldPageProtect     ;    // ����ڴ���Ϣ��ķ�ҳ����

}  BREAKPOINT,*PBREAKPOINT;

typedef struct DEBUGGEE
{
        BOOLEAN Stopped;
        BOOLEAN StoppedSystem;
        ULONG StoppedContext;

		CONTEXT BreakContext;

        BOOLEAN SingleStepNext;
        ULONG StoppedEip;

		//Ŀ����̵ľ����ID
        HANDLE hProcess;
        ULONG dwProcessId;

		//��ǰ�������̵߳�ID
		ULONG dwDebugThreadId;
		//��ǰ�������̵߳ľ��
		HANDLE hDebugThread;

		HANDLE hTheDebuggerThread;

		HANDLE hMutex;
        
        //�����̺߳��߳�ID�ı�
		//~ ULONG nThreads;
		//~ HANDLE *hThreads;
        //~ ULONG *dwThreadIds;
        //~ 
		List_T ThreadHandleTable;
		//���ڱ����ڴ���Ϣ
		List_T MemTable;


        char name[256];
        ULONG ModuleBase;
        ULONG EntryPoint;

		//�ж��Ƿ���Ϊ���ڴ�ϵ���жϵģ������Ҫ�ָ�
		BOOL IsForMemBreak;
		SIZE_T IndexMemoryBreaks;


        PVOID hooks;
        PVOID BreakPointBuffers;

		//����ϵ��
        BREAKPOINT bps[MAX_BPS];
		//�������Գ����жϵ�ʱ�������ж��Ƿ��ڶϵ���У�����ڣ���ָ��
		BREAKPOINT *cur_bps;
		//Ӳ���ϵ��
        PBREAKPOINT hws[4];
        
		//�ڴ�ϵ��
		PBREAKPOINT mbps[MAX_MEM_BREAKPOINT];

        //���浱ǰ���������ڴ���Ϣ
        MemNode *pCurrentMemNode;
} *PDEBUGGEE;

extern PDEBUGGEE moDbg; 


//�ɻ�ĺ���

//�����߳�
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

//���Ҷϵ��Ƿ��ǵ������û��µ�
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
						 MEM_BREAK_TYPE Type,//�ϵ�����:��/д
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


//----------------------------���صķָ���-------------------------------

#define __DISPLAY__
//#define OUTPUT_DEBUGEVENT_INFO(i,dst) 

//�¼���Ϣ���ձ�
typedef struct EventMsg EventMsg;

typedef DWORD (*ProcessTheEvent)(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
typedef void (*OutputTheEvent) ( void * stCPDI, FILE *f) ; 

DWORD ProcessEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// ������Ϣ.�����Խ�������ʱ�ᴥ��
DWORD OnDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// �����Խ��̴����߳�ʱʱ����
DWORD OnCreateThreadEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// �����Խ��̱�����ʱ����
DWORD OnCreateProcessDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// �������߳��˳�ʱ����
DWORD OnExitThreadDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// �����Խ����˳�ʱ����
DWORD OnExitProcessDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// �����Խ��̼���DLLʱ����
DWORD OnLoadDllDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// �����Խ���ж��DLLʱ����
DWORD OnUnLoadDllDebugEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// �����Խ������������Ϣʱ����
DWORD OnOutputDebugStringEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
// �������Խ��̳���ʱ����.
DWORD OnRipEvent(DEBUG_EVENT *dbgEvent,PDEBUGGEE dbg);
 

struct EventMsg
{
	DWORD dwEventId;
	ProcessTheEvent PeFun;
	OutputTheEvent Ote;
};

extern EventMsg EventFuncs[];

//----------------------------���صķָ���-------------------------------
//���������������Ϣ�ĺ���
// ��ϵ�к���ͨ������ȥ��Ӧ�ṹ��ָ��,�������Ļ����ؽṹ����Ϣ
void OutputCreateProcessEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputCreateThreadEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputExitThreadEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputExitProcessEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputDllLoadEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputDllUnLoadEvent ( DEBUG_EVENT *dbgEvent, FILE *f);
void OutputExceptionEvent ( DEBUG_EVENT *dbgEvent, FILE *f) ;
void OutputODSEvent ( HANDLE hProcess ,
                       OUTPUT_DEBUG_STRING_INFO * stODSI    ) ;
 
 
 
//--------------------------���صķָ���--------------------------------
//����������ʵ���ڴ�ϵ����õ������ݽṹ
//���ű�:
//�ڴ���Ϣ��
//
typedef struct _MemNode
{
	int             nID    ;                // Ψһ��ʶ,�����ʶͬ����ָ��moDbg�е��Զϵ���±�
	PVOID           BaseAddress ;           // ��ҳ��ʼ����ַ
	PVOID           AllocationBase ;        // ��ʼ��ַ���������Ľ��
	DWORD           AllocationProtect ;
	SIZE_T          RegionSize ;
	DWORD           State ;                 // ״̬
	DWORD           Protect ;               // ����
	DWORD           newProtect ;            // ������
	DWORD           Type ;
} MemNode, *PMemNode;

//�����ڴ��ҳ��Ϣ
BOOL UpdateMemTable(PDEBUGGEE dbg);

//��ȡ��һ��ָ��ĵ�ַ
VOID GetNextInstructAddr(PDEBUGGEE dbg,PULONG nextStruct);

//������������Ļص�����
void ClearHardBreakPoint(void **x, void *cl);
void FindThreadHandleMember(void **x, void *cl);
void DestroyThreadHandle(void **x, void *cl);
void FindMemNodeMemory(void **x,void *cl);
#endif
