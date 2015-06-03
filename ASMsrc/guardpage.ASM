include 'win32ax.inc'

.code

 start:
	xor ebx, ebx
	invoke VirtualAlloc,ebx,1,1000h,40h
	mov byte [eax], 0c3h
	push eax
	xchg ebp, eax
	invoke VirtualProtect,ebp,1,140h,esp
	push .exit
	push dword [fs:ebx]
	mov [fs:ebx], esp
	push .being_debugged
	;execution resumes at being_debugged
	;if ret instruction is executed
	jmp ebp
	.being_debugged:
		invoke	MessageBox,HWND_DESKTOP,"Debugger Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess, 0
	.exit:
		invoke	MessageBox,HWND_DESKTOP,"Debugger Not Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0

.end start
