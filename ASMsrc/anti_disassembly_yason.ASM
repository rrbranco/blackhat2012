; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
;
; This program was created to test branch to garbage byte (5.2)
; reference: "The Art of Unpacking" by Mark Vincent Yason
;

include 'win32ax.inc'

.code
	start:
		push	.jmp_real_01
		stc
		jnc	.jmp_fake_01
		retn

		.jmp_fake_01:
			db	0xff

		.jmp_real_01:
			mov	eax, [fs:0x18]
			push	.jmp_real_02
			clc
			jc	.jmp_fake_02
			retn

		.jmp_fake_02:
			db 0xff

		.jmp_real_02:
			mov	eax, [eax+0x30]
			movzx	eax, byte [eax+0x02]
			test	eax, eax
			jnz	.debugger_found
			jmp	.exit

		.debugger_found:
			invoke	MessageBox,HWND_DESKTOP,"Debugger Found!",invoke GetCommandLine,MB_OK
			invoke	ExitProcess, 0
		.exit:
			invoke	MessageBox,HWND_DESKTOP,"Debugger Not Found!",invoke GetCommandLine,MB_OK
			invoke	ExitProcess,0

	.end start