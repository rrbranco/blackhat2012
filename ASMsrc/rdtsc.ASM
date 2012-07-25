; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
; This program was created to test RDTSC instruction timing (3.25)
; references:
; "Anti-Unpacker Tricks" by Peter Ferrie
; "The Ultimate Anti-Debugging Reference" by Peter Ferrie
; "Windows Anti-Debug Reference" by Nicolas Falliere:
; http://www.symantec.com/connect/articles/windows-anti-debug-reference

include 'win32ax.inc'

.code

  start:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	rdtsc	; rdpmc or rdmsr (64 bits)
	xor	ecx,ecx
	add	ecx,eax
	rdtsc	; rdpmc or rdmsr (64 bits)
	sub	eax,ecx
	cmp	eax,0xFFF
	jnb    .being_debugged
	jmp    .exit

	.being_debugged:
		invoke	MessageBox,HWND_DESKTOP,"Debugger Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess, 0
	.exit:
		invoke	MessageBox,HWND_DESKTOP,"Debugger Not Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0

  .end start
