; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
;
; This program was created only to test stealth import of windows API (4.4)
; it is by no means a fully functional program to be used in order to import windows APIs
; This program was created to test ntglobal access (3.1)
; reference: Alexey Lyashko - Stealth Import of Windows API
; http://syprog.blogspot.com.br/2011/10/stealth-import-of-windows-api.html

include 'win32ax.inc'

.data
	mz db "MZ"
	pe db "PE"

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

	mov	eax,[fs:0]
	;mov     ebx,0FFFFFFFFh

	.search_default_handler:
		cmp	dword [eax], 0xFFFFFFFF
		jz	.found_default_handler
		mov	eax, [eax]
		jmp	.search_default_handler

	.found_default_handler:
	       mov	eax, [eax+4]
	       and	eax, 0xFFFF0000

	.look_for_mz:
		cmp	word [eax], 'MZ'
		jz     .got_mz
		sub    eax, 0x10000
		jmp    .look_for_mz

	.got_mz:
		mov	bx, [eax+0x3C]
		movzx	ebx,bx
		add	eax,ebx
		mov	bx, 'PE'
		movzx	ebx, bx
		cmp    [eax], ebx
		jz     .found_pe
		jmp    .not_found_pe

	.found_pe:
		add	eax, 0x78
		invoke	MessageBox,HWND_DESKTOP,"PE signature found!",invoke GetCommandLine,MB_OK
		pop	esi
		pop	edi
		pop	edx
		pop	ecx
		pop	ebx
		pop	eax
		invoke	ExitProcess,NULL

	.not_found_pe:
		invoke	MessageBox,HWND_DESKTOP,"PE signature not found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0

  .end start