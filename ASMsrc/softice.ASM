; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
; This program was created to test softice anti-debugging detection (3.21)
; reference: "Anti-Unpacker Tricks" by Peter Ferrie


include 'win32ax.inc'

.code

  start:
	xor	eax, eax
	push	dword [fs:0]
	mov	[fs:0],esp
	int1
	.exception:
		mov	eax,[esp+0x4]
		cmp	dword[eax], 0x80000004
		je	.being_debugged
		jmp	.exit
	.being_debugged:
		invoke	MessageBox,HWND_DESKTOP,"Debugger Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess, 0
	.exit:
		invoke	MessageBox,HWND_DESKTOP,"Debugger Not Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0

  .end start
