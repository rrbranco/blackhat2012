; EP not exec

include 'win32ax.inc'

.code

  start:
	invoke	MessageBox,HWND_DESKTOP,"Hello EP not exec!",invoke GetCommandLine,MB_OK
	invoke	ExitProcess,0

  .end start