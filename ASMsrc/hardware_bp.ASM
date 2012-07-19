; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
; This program was created to test hardware breakpoint detection (3.13)
; reference: "Anti-Unpacker Tricks" by Peter Ferrie


include 'win32ax.inc'

.code

  start:
	push	.exception_handler
	push	dword [fs:0]
	mov	[fs:0],esp

	xor	eax,eax
	mov	dword [eax], 0
	pop	dword [fs:0]
	add	esp,4
	test	eax,eax
	jnz	.being_debugged
	jmp	.exit


	.exception_handler:
	mov	eax,[esp+0xc]
	cmp	dword [eax+0x04],0
	jne	.being_debugged
	cmp	dword [eax+0x08],0
	jne	.being_debugged
	cmp	dword [eax+0x0C],0
	jne	.being_debugged
	cmp	dword [eax+0x10],0
	jne	.being_debugged
	jmp	.exit

	.being_debugged:
		invoke	MessageBox,HWND_DESKTOP,"Hardwae BP Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess, 0
	.exit:
		invoke	MessageBox,HWND_DESKTOP,"Hardware BP Not Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0

  .end start
