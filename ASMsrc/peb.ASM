; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
;
; This program was created to test PEB Being Debuged access (3.2)
; reference: "Anti-Unpacker Tricks" by Peter Ferrie

include 'win32ax.inc'

.code

  start:
	push	dword [fs:0x30]
	pop	eax
	push	dword [eax+0x2]
	pop	ebx
	cmp	bl, 0
	jne	.being_debugged
	jmp	.exit

	.being_debugged:
		invoke	MessageBox,HWND_DESKTOP,"Debugger Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess, 0
	.exit:
		invoke	MessageBox,HWND_DESKTOP,"Debugger Not Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0
  .end start
