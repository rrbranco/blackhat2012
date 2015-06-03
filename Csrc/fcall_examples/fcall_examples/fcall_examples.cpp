/* Qualys Vulnerabliity & Malware Research Labs (VMRL)
Blackhat 2012 Presentation Samples
TiTle: 	A Scientific (but non academic) study of how malware employs anti-debugging,
		anti-disassembly and anti-virtualization technologies
Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
		 Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
		 Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>

This is the VS 2010 project implemented to test anti-debugging techniques which were
not implemented in ASM, those are just proof-of-concept (POC) and are not intended to
be fully functional.

The functions are basically divided in three groups:
	Functions (f) which is the call to the function by itself, only calling the function can be a technique.
	Parameters (p) which depends to check the function parameter in order to identify the technique.
	Sequence (s) which is the sequence of functions calls like calling a function two or more times.

*/

#include "windows.h"
#include "conio.h"
#include <tchar.h>
#include <tlhelp32.h>
#include <time.h>
#include <WinUser.h>
#include <stdio.h>
#include <stdlib.h>
#include <Psapi.h>

#include "defs.h"
#include "ntDefs.h"
#include "defs2.h"

// RtlQueryProcessDebugInformation
#define WIN32_LEAN_AND_MEAN

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"psapi.lib")
#pragma comment(lib,"user32.lib")

//CsrGetProcessId
typedef DWORD_PTR ( NTAPI *CGPID )( );
typedef DWORD_PTR ( NTAPI *DBGBREAKPOINT ) ();

PSYSTEM_PROCESS_INFORMATION getProcessInfo() {
	ULONG ulSize;
	LONG status;
	LPBYTE pBuffer;
	ULONG bufferSize = 0;

	do {
		bufferSize += 0x10000;
		pBuffer = (LPBYTE)malloc(bufferSize);

	status = NtQuerySystemInformation(SystemProcessInformation, pBuffer, bufferSize, &ulSize);
	if (status == 0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/) {
		free(pBuffer);
		}
	} while (status == 0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/);

	if (status == 0x00) {
		return (PSYSTEM_PROCESS_INFORMATION)pBuffer;
	}

	return NULL;
}

// 3.2
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void fIsDebuggerPresent() {
	if (IsDebuggerPresent())
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}

// 3.3
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void fCheckRemoteDebuggerPresent() {

	BOOL isdbg = FALSE;
		
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &isdbg);
	if (isdbg)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}

// 3.5
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void pProcessDebugPort() {
	HANDLE proc;
	NTSTATUS ntStatus;
	DWORD debugport = NULL;

	proc = GetCurrentProcess();
	ntStatus = NtQueryInformationProcess(proc,ProcessDebugPort,&debugport,sizeof(debugport),NULL);
	if (ntStatus != 0)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}

// 3.6
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void pDebugObjectHandle() {

	HANDLE proc;
	NTSTATUS ntStatus;
	HANDLE hDebugHandle = NULL;
	
	proc = GetCurrentProcess();
	ntStatus = NtQueryInformationProcess(proc,ProcessDebugObjectHandle,&hDebugHandle,sizeof(hDebugHandle),NULL);

	if (hDebugHandle)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}

// 3.7
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void pProcessDebugFlags() {
	
	HANDLE proc;
	NTSTATUS ntStatus;
	HANDLE hDebugFlags = NULL;

	proc = GetCurrentProcess();
	ntStatus = NtQueryInformationProcess(proc,ProcessDebugFlags,&hDebugFlags,sizeof(hDebugFlags),NULL);
	if (hDebugFlags == FALSE)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}

// 3.8
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void pSystemKernelDebuggerInformation() {
	HANDLE proc;
	NTSTATUS ntStatus;
	DWORD hKdbg = NULL;
	PULONG hKdbgRetLenght = NULL;
	
	proc = GetCurrentProcess();
	ntStatus = NtQuerySystemInformation(SystemKernelDebuggerInformation,&hKdbg,sizeof(hKdbg),hKdbgRetLenght);

	if (hKdbg)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");

}

// 3.9
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void sCsrGetProcessId_OpenProcess() {
	DWORD pid = NULL;
	CGPID CsrGetProcessId = ( CGPID ) GetProcAddress( GetModuleHandle( _T("ntdll.dll") ), "CsrGetProcessId" );
	if (OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, CsrGetProcessId()) != NULL)
		printf("SeDebugPrivilige acquired\n");
	else
		printf("Unable to grab SeDebugPrivilege\n");
}

// 3.10
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void sCreateDesktop_SwitchDesktop() {
	HDESK myDesktop = NULL;
	BOOL res = FALSE;

	myDesktop = CreateDesktop(_T("mydesktop"), NULL, NULL, 0, DESKTOP_CREATEWINDOW | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP, NULL);
	if (myDesktop != NULL)
		res = SwitchDesktop(myDesktop);
			if (res)
				printf("SwitchDesktop works\n");
}

// 3.11
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void sCreateProcess_ContinueDebugEvent() {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	si.dwFlags = 0x1;
	si.wShowWindow = 0x0;
	ZeroMemory( &pi, sizeof(pi) );

	if (CreateProcess( L"C:\\windows\\system32\\calc.exe",
						NULL,
						NULL,
						NULL,
						FALSE,
						DEBUG_PROCESS,
						NULL,
						NULL,
						&si,
						&pi )){
		printf("PID = %d\n", pi.dwProcessId);
		ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE);
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);	
	} else
		printf("CreateProcess failed (%d).\n", GetLastError());
}

// 3.12
// references:
// "The Ultimate Anti-Debugging Reference" by Peter Ferrie
// "Anti-Unpacker Tricks - Part Eight" by Peter Ferrie
// Evilcodecave's Weblog - RtlQueryProcessHeapInformation As Anti-Dbg Trick:
//	http://evilcodecave.wordpress.com/2009/04/
void fRtlQueryProcessDebugInformation() {
	PDEBUG_BUFFER buffer;
	NTSTATUS ntStatus;
	ULONG pdi_heaps = 0x04;
	ULONG pdi_heap_blocks = 0x10;

	buffer = RtlCreateQueryDebugBuffer(0,FALSE);

	ntStatus = RtlQueryProcessDebugInformation(GetCurrentProcessId(),PDI_HEAPS|PDI_HEAP_BLOCKS,buffer);
	PDEBUG_HEAP_INFORMATION heapInfo = PDEBUG_HEAP_INFORMATION(PULONG(buffer->HeapInformation) + 1);

	if (heapInfo->Flags == 0x50000062)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");

	RtlDestroyQueryDebugBuffer(buffer);
}

// 3.12
// references:
// "The Ultimate Anti-Debugging Reference" by Peter Ferrie
// "Anti-Unpacker Tricks - Part Eight" by Peter Ferrie
// Evilcodecave's Weblog - RtlQueryProcessHeapInformation As Anti-Dbg Trick:
//	http://evilcodecave.wordpress.com/2009/04/
void fRtlQueryProcessHeapInformation() {
	PDEBUG_BUFFER buffer;
	
	buffer = RtlCreateQueryDebugBuffer(0,FALSE);

	RtlQueryProcessHeapInformation(buffer);

	if (buffer->RemoteSectionBase == (PVOID) 0x50000062)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}


// 3.14
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void sOutputDebugString_GetLastError () {
	OutputDebugStringA("Hi Debugger");
	if (GetLastError() == 0)
		printf("Debugger detected\n");
}

// 3.15
// references:
// "Anti-Unpacker Tricks" by Peter Ferrie
// "The Art of Unpacking" by Mark Vincent Yason
void fBlockInput() {
	BOOL lock = TRUE;
	BOOL release = FALSE;

	BlockInput(lock);
	Sleep(5);
	BlockInput(release);
}

// 3.16 (1)
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
int sGetCurrentProcessId_CreateToolhelp32Snapshot() {
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	TCHAR explorer[13] = TEXT("explorer.exe");
	DWORD myPid = NULL;
	DWORD explorerPid = NULL;
	DWORD myParentPid = NULL;

	myPid = GetCurrentProcessId();
	if (myPid == NULL) {
		printf("ERROR: Get CurrentProcessId()\n");
		return 1;
	}

	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE ) {
		printf("ERROR: call CreateToolhelp32Snapshot\n");
		CloseHandle( hProcessSnap );
		return 2;
	}

	pe32.dwSize = sizeof( PROCESSENTRY32 );

	if( !Process32First( hProcessSnap, &pe32 ) ) {
		printf("ERROR: call Process32First\n");
		CloseHandle (hProcessSnap);
		return 3;
	}

	do {
		if (_tcscmp(pe32.szExeFile, explorer) == 0) {// found explorer.exe
			explorerPid = pe32.th32ProcessID;
		}
		if ((pe32.th32ProcessID == myPid) && (explorerPid != NULL)) {
			myParentPid = pe32.th32ParentProcessID;
			break;
		}

	} while ( Process32Next(hProcessSnap, &pe32));

	if (myParentPid != NULL) {
		if (myParentPid == explorerPid)
			printf("Parent is explorer.exe\n");
		else
			printf("Parent is NOT explorer.exe\n");
	} else {
		printf("ERROR: Unable to grab parent Pid\n");
		CloseHandle( hProcessSnap );
		return 4;
	}
	
	CloseHandle( hProcessSnap );
	return 0;

}

// 3.16 (2)
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
int spGetProcessId_NtQuerySystemInformation() {
	DWORD explorerPid = NULL;
	DWORD myPid = NULL;
	const wchar_t explorer[13] = TEXT("explorer.exe");

	myPid = GetCurrentProcessId();
	if (myPid == NULL) {
		printf("ERROR: Grab current process id\n");
		return 2;
	}

	PSYSTEM_PROCESS_INFORMATION head = getProcessInfo();

	if (head != NULL) {
		while (head != NULL) {
			if (head->ImageName.Buffer != NULL) 
				if (wcscmp(head->ImageName.Buffer, explorer) == 0)
					explorerPid = (DWORD)head->ProcessId;

			if ((head->ProcessId == (HANDLE)myPid) && (explorerPid != NULL))
				break;
			if(head->NextEntryOffset == 0)
				head = NULL;
			else
				head = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)head + head->NextEntryOffset);
		}
	}

	if (head->ProcessId != NULL)
		if ((DWORD)head->ProcessId != myPid) {
			printf("ERROR: Unable to grab current process id\n");
			return 1;
		}

	if ((explorerPid != NULL) && (head->InheritedFromProcessId != NULL)) {
		if (explorerPid == (DWORD)head->InheritedFromProcessId)
			printf("Parent process is explorer.exe:\n\n");
		else
			printf("Parent process is NOT explorer.exe:\n\n");
		printf("Explorer pid = %d\n", explorerPid);
		printf("Current pid = %d\n", head->ProcessId);
		printf("Current parent = %d\n", head->InheritedFromProcessId);
		return 0;
	} else {
		printf("ERROR: Unable to grab explorer PID or parent process ID\n");
		return 3;
	}
}

// 3.16 (3)
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void sGetShellWindow_GetWindowThreadProcessId_NtQuerySystemInformation() {
	HWND window = NULL;
	DWORD pid = NULL;
	PROCESS_BASIC_INFORMATION pBasicInfo;
	DWORD ReturnLength = NULL;
	NTSTATUS ntStatus = NULL;

	window = GetShellWindow();
	if (window != NULL)
		GetWindowThreadProcessId(window, &pid);
		if (pid != NULL) 
			printf("PID of explorer.exe = %d\n", pid);
			ntStatus = NtQueryInformationProcess(GetCurrentProcess(),ProcessBasicInformation,&pBasicInfo,sizeof(PROCESS_BASIC_INFORMATION),&ReturnLength);
			if (ntStatus >= 0)
				printf("Current Process Inherit PID: %d\n",pBasicInfo.InheritedFromUniqueProcessId);
				if (pid != pBasicInfo.InheritedFromUniqueProcessId)
					printf("Parent process is not explorer.exe\n");
				else
					printf("Parent process is explorer.exe\n");
}

// 3.17
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void pCreateFile() {
	HANDLE hFile = NULL;

	hFile = CreateFile(_T("\\\\.\\NTICE"),0,0,0,OPEN_EXISTING,0,0);
	if (hFile != INVALID_HANDLE_VALUE)
		printf("Existing SoftICE Handle\n");
	else
		printf("SoftICE not found\n");
}

// 3.18
// references:
// "Anti-Unpacker Tricks" by Peter Ferrie
// "The Art Of Unpacking" by Mark Vincent Yason
void pOutputDebugString() {
	OutputDebugString(_T("%s%s%s%s%s%s%s%s%s")); // crashed OllyDBG 1.10
}

// 3.19
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void pFindWindow() {

	HANDLE hJanela = NULL;

	hJanela = FindWindow(_T("OLLYDBG"), NULL);
	if (hJanela != NULL)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");

}

// 3.20
// references:
// "Anti-Unpacker Tricks" by Peter Ferrie
// "The Ultimate Anti-Debugging Reference" by Peter Ferrie
int sSuspendThread() {
	HANDLE hThreadSnap;
	HANDLE hThread;
	THREADENTRY32 te32;
					
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	TCHAR explorer[13] = TEXT("explorer.exe");
	DWORD myPid = NULL;
	DWORD explorerPid = NULL;
	DWORD myParentPid = NULL;

	myPid = GetCurrentProcessId();
	if (myPid == NULL) {
		printf("ERROR: Get CurrentProcessId()\n");
		return 1;
	}

	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE ) {
		printf("ERROR: call CreateToolhelp32Snapshot\n");
		CloseHandle( hProcessSnap );
		return 2;
	}

	pe32.dwSize = sizeof( PROCESSENTRY32 );

	if( !Process32First( hProcessSnap, &pe32 ) ) {
		printf("ERROR: call Process32First\n");
		CloseHandle (hProcessSnap);
		return 3;
	}

	do {
		if (_tcscmp(pe32.szExeFile, explorer) == 0) {// found explorer.exe
			explorerPid = pe32.th32ProcessID;
		}
		if ((pe32.th32ProcessID == myPid) && (explorerPid != NULL)) {
			myParentPid = pe32.th32ParentProcessID;
			break;
		}

	} while ( Process32Next(hProcessSnap, &pe32));

	if (myParentPid != NULL) {
		if (myParentPid == explorerPid)
			printf("Parent is explorer.exe\n");
		else {
			printf("Parent is NOT explorer.exe\n");
			hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if( hThreadSnap == INVALID_HANDLE_VALUE ) {
				printf("ERROR: call CreateToolhelp32Snapshot\n");
				CloseHandle( hProcessSnap );
				return 5;
			}

			te32.dwSize = sizeof(te32);

			if (Thread32First(hThreadSnap, &te32)) {
				do {
					if (te32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te32.th32OwnerProcessID)) {
						if (te32.th32OwnerProcessID == myParentPid) {
							printf("Crashing main Thread of parent process\n");
							Sleep(2);
							hThread = OpenThread(THREAD_SUSPEND_RESUME,0,te32.th32ThreadID);
							if ((SuspendThread(hThread)) != -1)
								printf("Explorer.exe main thread Suspended\n");
						}
					}
					te32.dwSize = sizeof(te32);
				} while (Thread32Next(hThreadSnap, &te32));
			}
			CloseHandle(hThreadSnap);
		}
	} else {
		printf("ERROR: Unable to grab parentPid\n");
		CloseHandle( hProcessSnap );
		return 4;
	}
	
	CloseHandle( hProcessSnap );
	return 0;

}

// 3.23
// references:
// "Anti-Unpacker Tricks" by Peter Ferrie
// "The Art Of Unpacking" by Mark Vincent Yason
// "Windows Anti-Debug Reference" by Nicolas Falliere:
// http://www.symantec.com/connect/articles/windows-anti-debug-reference    
void fSetUnhandledExceptionFilter() {

	SetUnhandledExceptionFilter(NULL);
	_asm int 3;
	printf("Debugger detected\n");
}

// 3.24
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
int psVirtuaAlloc_VirtualProtect() {
	LPVOID lpvAddr;
	DWORD dwPageSize;
	DWORD dwOldProtect;
	BOOL vprotect;
	SYSTEM_INFO sSysInfo;

	GetSystemInfo(&sSysInfo);
	dwPageSize = sSysInfo.dwPageSize;

	lpvAddr = VirtualAlloc(NULL, dwPageSize, MEM_COMMIT , PAGE_EXECUTE_READWRITE);
	if (lpvAddr == NULL) {
		_tprintf(TEXT("Virtual alloc failed. Error %1d\n"), GetLastError());
		return 1;
	}

	vprotect = VirtualProtect(lpvAddr, dwPageSize, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect);
	if (!vprotect) {
		_ftprintf(stderr, TEXT("Cannot protect to PAGE_GUARD at %lp, error=0x%1x\n"), lpvAddr, GetLastError());
		return 1;
	} else {
		_ftprintf(stderr, TEXT("PAGE_GUARD Achieved at %lp\n"), lpvAddr);
		return 0;
	}
}

// 3.25 GetTickCount
// reference: "The Ultimate Anti-Debugging Reference" by Peter Ferrie
void sGetTickCount() {
	DWORD initial = NULL;
	DWORD end = NULL;

	initial = GetTickCount();
	end = GetTickCount();
	if ((end - initial) >= 10)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}

// 3.25 timeGetTime
// reference: "The Ultimate Anti-Debugging Reference" by Peter Ferrie
void stimeGetTime() {
	DWORD initial = NULL;
	DWORD end = NULL;

	initial = timeGetTime();
	end = timeGetTime();
	if ((end - initial) >= 10)
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}

// 3.25 GetSystemTime
// reference: "The Ultimate Anti-Debugging Reference" by Peter Ferrie
void sGetSystemTime() {
	
	SYSTEMTIME initial,end;
	FILETIME finitial, fend;
	GetSystemTime(&initial);
	GetSystemTime(&end);
	SystemTimeToFileTime(&initial, &finitial);
	SystemTimeToFileTime(&end, &fend);
	if (((fend.dwHighDateTime - finitial.dwHighDateTime) > 10) || ((fend.dwLowDateTime - finitial.dwLowDateTime) > 10))
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}

// 3.25 GetLocalTime
// reference: "The Ultimate Anti-Debugging Reference" by Peter Ferrie
void sGetLocalTime() {
	
	SYSTEMTIME initial,end;
	FILETIME finitial, fend;
	GetLocalTime(&initial);
	GetLocalTime(&end);
	SystemTimeToFileTime(&initial, &finitial);
	SystemTimeToFileTime(&end, &fend);
	if (((fend.dwHighDateTime - finitial.dwHighDateTime) > 10) || ((fend.dwLowDateTime - finitial.dwLowDateTime) > 10))
		printf("Debugger detected\n");
	else
		printf("Debugger not detected\n");
}


// 3.25 QueryPerformanceCounter
// reference: "The Ultimate Anti-Debugging Reference" by Peter Ferrie
// reference: http://www.shell-storm.org/papers/files/764.pdf
void sQueryPerformanceCounter() {
	LARGE_INTEGER initial;
	LARGE_INTEGER end;
	if (QueryPerformanceCounter(&initial))
		if (QueryPerformanceCounter(&end)) {
			printf("\ninitial.LowPart %02d \n" , initial.LowPart);
			printf("\nend.LowPart %02d \n" , end.LowPart);
			if ((end.QuadPart - initial.QuadPart) > 0x10)
				printf("Debugger detected\n");
			else
				printf("Debugger not detected\n");
		} else
			printf("ERROR QueryPerformanceCounter call\n");
	else
		printf("ERROR QueryPerformanceCounter call\n");
}

// 3.27
// references:
// "Anti-Unpacker Tricks" by Peter Ferrie
// "The Art Of Unpacking" by Mark Vincent Yason
// "Windows Anti-Debug Reference" by Nicolas Falliere:
// http://www.symantec.com/connect/articles/windows-anti-debug-reference    
void pThreadHideFromDebugger() {
	HANDLE hThread = NULL;
	NTSTATUS ntStatus;

	hThread = GetCurrentThread();

	ntStatus = NtSetInformationThread(hThread,ThreadHideFromDebugger,NULL,0);
}

// 3.28
// reference: "The Ultimate Anti-Debugging Reference" by Peter Ferrie
void fNtSetDebugFilterState() {
	NTSTATUS ntStatus;
	ntStatus = NtSetDebugFilterState(0,0,TRUE);

	if (ntStatus != STATUS_SUCCESS)
		printf("Debugger not detected\n");
	else
		printf("Debugger detected\n");
}

// 3.31
// reference: "Anti-Unpacker Tricks" by Peter Ferrie
void sCreateProcess_CreateMutex() {
	HANDLE hMutex = NULL;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	si.dwFlags = 0x1;
	si.wShowWindow = 0x0;
	ZeroMemory( &pi, sizeof(pi) );

	hMutex = CreateMutex(NULL, FALSE, TEXT("mymutex"));
	if (hMutex == NULL) 
		printf("ERROR Create Mutex\n");
	else
		if (GetLastError() != ERROR_ALREADY_EXISTS) {
			if ( !CreateProcess( L"C:\\windows\\system32\\calc.exe",
						NULL,
						NULL,
						NULL,
						FALSE,
						CREATE_NEW_CONSOLE,
						NULL,
						NULL,
						&si,
						&pi )) {
				printf("ERROR CreateProcess failed (%d).\n", GetLastError());
			} else {
				WaitForSingleObject(pi.hProcess, INFINITE);
				ExitProcess(0);
			}
	}
}

// 3.32
// reference: http://waleedassar.blogspot.com.br/2011/12/debuggers-anti-attaching-techniques.html
void fDbgBreakPoint() {
	DWORD dwOldProtect;
	unsigned char* DbgBreakPoint=(unsigned char*)GetProcAddress(GetModuleHandle(_T("ntdll.dll") ), "DbgBreakPoint");
	VirtualProtect(DbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*DbgBreakPoint = 0x90;
}

int _tmain(int argc, _TCHAR* argv[])
{
	unsigned int opt = 0;
	unsigned int ret = 0;
	BOOL vpc = false;
	printf("Anti-Debugging POCs\n\n");
	printf("1  - 3.2 IsDebuggerPresent\n");
	printf("2  - 3.3 CheckRemoteDebuggerPresent \n");
	printf("3  - 3.5 NtQueryInformationProcess – ProcessDebugPort\n");
	printf("4  - 3.6 Debug Objects – ProcessDebugObjectHandle Class\n");
	printf("5  - 3.7 Debug Objects – ProcessDebugFlags Class\n");
	printf("6  - 3.8 NtQuerySystemInformation – SystemKernelDebuggerInformation\n");
	printf("7  - 3.9 OpenProcess – SeDebugPrivilege\n");
	printf("8  - 3.10 Alternative Desktop\n");
	printf("9  - 3.11 Self-Debugging\n");
	printf("10 - 3.12 RtlQueryProcessDebugInformation\n");
	printf("11 - 3.12 RtlQueryProcessHeapInformation\n");
	printf("12 - 3.14 OutputDebugString\n");
	printf("13 - 3.15 BlockInput\n");
	printf("14 - 3.16 Parent Process - GetCurrentProcessId() + CreateToolhelp32Snapshot()\n");
	printf("15 - 3.16 Parent Process - GetCurrentProcessId() + NtQuerySystemInformation(SystemProcessInformation)\n");
	printf("16 - 3.16 Parent Process - GetShellWindow()+ GetWindowThreadProcessId() + NtQueryInformationProcess(ProcessBasicInformation)\n");
	printf("17 - 3.17 Device Names\n");
	printf("18 - 3.18 OllyDbg – OutputDebugString\n");
	printf("19 - 3.19 FindWindow\n");
	printf("20 - 3.20 SuspendThread\n");
	printf("21 - 3.23 UnhandledExceptionFilter\n");
	//printf("22 - 3.24 Guard Pages\n");
	printf("23 - 3.25 Execution Timing - GetTickCount()\n");
	printf("24 - 3.25 Execution Timing - timeGetTime\n");
	printf("25 - 3.25 Execution Timing - GetSystemTime()\n");
	printf("26 - 3.25 Execution Timing - GetLocalTime()\n");
	printf("27 - 3.25 Execution Timing - QueryPerformanceCounter()\n");
	printf("28 - 3.27 Thread Hiding\n");
	printf("29 - 3.28 NtSetDebugFilterState\n");
	printf("30 - 3.31 Self-Execution\n");
	printf("31 - 3.32 DbgBreakpoint Overwrite\n\n");
	scanf_s("%d", &opt);
	switch (opt) {
	case 1:
		fIsDebuggerPresent();
		break;
	case 2:
		fCheckRemoteDebuggerPresent();
		break;
	case 3:
		pProcessDebugPort();
		break;
	case 4:
		pDebugObjectHandle();
		break;
	case 5:
		pProcessDebugFlags();
		break;
	case 6:
		pSystemKernelDebuggerInformation();
		break;
	case 7:
		sCsrGetProcessId_OpenProcess();
		break;
	case 8:
		sCreateDesktop_SwitchDesktop();
		break;
	case 9:
		sCreateProcess_ContinueDebugEvent();
		break;
	case 10:
		fRtlQueryProcessDebugInformation();
		break;
	case 11:
		fRtlQueryProcessHeapInformation();
		break;
	case 12:
		sOutputDebugString_GetLastError();
		break;
	case 13:
		fBlockInput();
		break;
	case 14:
		ret = sGetCurrentProcessId_CreateToolhelp32Snapshot();
		break;
	case 15:
		spGetProcessId_NtQuerySystemInformation();
		break;
	case 16:
		sGetShellWindow_GetWindowThreadProcessId_NtQuerySystemInformation();
		break;
	case 17:
		pCreateFile();
		break;
	case 18:
		pOutputDebugString();
		break;
	case 19:
		pFindWindow();
		break;
	case 20:
		ret = sSuspendThread();
		break;
	case 21:
		fSetUnhandledExceptionFilter();
		break;
	// case 22:
	// 	ret = psVirtuaAlloc_VirtualProtect();
	// 	break;
	case 23:
		sGetTickCount();
		break;
	case 24:
		stimeGetTime();
		break;
	case 25:
		sGetSystemTime();
		break;
	case 26:
		sGetLocalTime();
		break;
	case 27:
		sQueryPerformanceCounter();
		break;
	case 28:
		pThreadHideFromDebugger();
		break;
	case 29:
		fNtSetDebugFilterState();
		break;
	case 30:
		sCreateProcess_CreateMutex();
		break;
	case 31:
		fDbgBreakPoint();
		break;
	default:
		printf("Invalid option\n");
		break;
	}
	_getch();
	return 0;
}