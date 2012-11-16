; Created for Hackers 2 Hackers Conference (H2HC) 2012 - 9th Edition
; Training: Windows Malware Reverse Engineering
;
; Authors:
; Rodrigo Rubira Branco
; Gabriel Negreira Barbosa
;
; Jump to the middle of an instruction
;
; Based on:
; Nick Harbour - Advanced Software Armoring and Polymorphic Kung-Fu

include 'win32ax.inc'

.code

  start:
	; Useles pushes. They are here only to pop later.
	; The idea of such pops is to make it clear, in the debugger, the destination of the "jmp 5" inside the mov instruction
	push 0x1
	push 0x2
	push 0x3

	mov ax,0x05eb
	xor eax,eax

	; jump to "jmp 5" (0xeb 0xe5)
	; last bytes of mov instruction is 0xeb 0xe5
	; such "jmp 5" redirects the flow to the "; rest of the code"
	jz $-4

	db 0xe8 ; garbage byte

	; rest of the code

	; pops described in the pushes comment
	pop eax
	pop eax
	pop eax

	invoke	MessageBox,HWND_DESKTOP,"Hooray!",invoke GetCommandLine,MB_OK
	invoke	ExitProcess, 0
  .end start
