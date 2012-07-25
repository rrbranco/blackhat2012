; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
include 'win32ax.inc'

.code

  start:
	nop
	nop
	nop
	call	.function
	db	0x6a
	.correct_return:
		pop eax
		invoke	MessageBox,HWND_DESKTOP,"This is where should return",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0
	.function:
		push	DWORD .correct_return
		ret
  .end start
