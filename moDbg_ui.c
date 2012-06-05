#define _CRT_SECURE_NO_WARNINGS

#include "global_header.h"
#include "moDbg.h"
#include "spydbg.h"
#include "libdasm.h"
#include "list.h"

#define __DISPLAY__

BOOL WINAPI ConsoleHandler (ULONG Event)
{
        switch (Event)
        {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
                //~ if (hCmdThread)
                //~ {
                        //~ TerminateThread (hCmdThread, 0);

                        //~ char *cmd = "<unk>";

                        //~ if (tharg.argv && tharg.argv[0])
                                //~ cmd = tharg.argv[0];

                        //~ printf("! Ctrl-C: Forced command '%s' termination\n", cmd);
                //~ }
                puts("break event");

                return TRUE;    // don't execute next handler

        case CTRL_CLOSE_EVENT:
                //~ DO_COMMAND_NOARG (exit);
				puts("close event");
                break;
        }

        return FALSE;
}


BOOL CtrlHandler( DWORD fdwCtrlType ) 
{ 
	switch( fdwCtrlType ) 
	{ 
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT: 
		printf( "Ctrl-C event\n\n" );
		return( TRUE );

		// CTRL-CLOSE: confirm that the user wants to exit. 
	case CTRL_CLOSE_EVENT: 
		Beep( 600, 200 ); 
		printf( "Ctrl-Close event\n\n" );
		return( TRUE ); 

		// Pass other signals to the next handler. 
	case CTRL_BREAK_EVENT: 
		Beep( 900, 200 ); 
		printf( "Ctrl-Break event\n\n" );
		return FALSE; 

	case CTRL_LOGOFF_EVENT: 
		Beep( 1000, 200 ); 
		printf( "Ctrl-Logoff event\n\n" );
		return FALSE; 

	case CTRL_SHUTDOWN_EVENT: 
		Beep( 750, 500 ); 
		printf( "Ctrl-Shutdown event\n\n" );
		return FALSE; 

	default: 
		return FALSE; 
	} 
} 



int main(int argc,char *argv[])
{

	char command[1024] = "";
	char prevcmd[1024] = "";

	char *args[200] = {0};

	char *cmdptr;
	char *cmdargs;
	ULONG l;

	int arg;
	char *prev;

	char *sp;

	int i;
	
	printf("//==============================     \n");
	printf("//   [c] float, 2010                 \n");
	printf("// moDbg console debugger " __MODBG_VER " \n");

	printf("//==============================     \n");
	printf("\n");
	printf("~ Initializing\n");
	
	
	SetConsoleCtrlHandler((PHANDLER_ROUTINE) CtrlHandler,TRUE);


//#这儿需要添加处理argv和argc进行处理并调用的代码

	for(;;)
	{
//		lstrcpy (cdbg_last_err, "Success");

		printf("\nmoDbg> ");

		memset(command,0,sizeof(command));

		fgets (command, sizeof(command)-1, stdin);
		
		i = 0;
		sp = command;
		while(1)
		{
			if (*sp == ' ' || *sp == '\n')
			{
				sp++;
			}
			else
			{
				break;
			}

		}


		strcpy(command,sp);

		strlen(command);

		//判断是否为回车
		if (strlen(command) == 0 || command[0] == 0x0a)
		{
			continue;
		}

		//
		// Delete first spaces.
		//

		for (cmdptr = command; isspace(*cmdptr); cmdptr++);

		//
		// Delete last spaces.
		//

		l = strlen(cmdptr);
		while (isspace(cmdptr[l-1]))
		{
			cmdptr[l-1] = 0;
			l--;
		}

		if (strlen(cmdptr)==0)
		{
			strcpy(command, prevcmd);
			cmdptr = command;
		}
		else
		{
			strcpy (prevcmd, cmdptr);
		}

		//
		// Parse command
		//

		arg=0;
		prev = cmdptr;

		cmdargs = 0;

		for (sp=cmdptr; ; sp++)
		{
			if (*sp == 0)
			{
				args[arg++] = prev;
				break;
			}

			if (isspace(*sp))
			{
				*(sp++) = 0;
				args[arg++] = prev;

				while (isspace(*sp))
					sp++;

				if (cmdargs == NULL)
					cmdargs = sp;

				prev = sp;
			}
		}


		i = 0;
		while (i < arg)
		{
	//		printf("%s\n",args[i]);
			i++;
		}
		
//		printf("%d\n",arg);

		for (i=0; CommandTable[i].handler; i++)
		{
			if (!stricmp(args[0], CommandTable[i].name))
			{
				CommandTable[i].handler (arg,args);
						//执行exit指令
				if (!_stricmp(args[0], "exit"))
					goto END;

			}
		}
	}
END:
	return 0;
}

#define __END
