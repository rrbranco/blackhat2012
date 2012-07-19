; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
; This program was created to test detection of instruction counting implemented by tElock  (3.29)
; references:
; "Anti-Unpacker Tricks" by Peter Ferrie
; "The Ultimate Anti-Debugging Reference" by Peter Ferrie

include 'win32ax.inc'

.code

  start:
	xor	eax,eax
	push	.exception
	push	dword [fs:eax]
	mov	[fs:eax], esp
	int3	; force an exception
	.labelone:
		nop
		nop
		nop
		nop
	cmp	al, 4  ; when no hardware breakpoint is set 0x4 is returned in EAX
	jne	.being_debugged
	jmp	.exit

	.exception:
		push	edi
		mov	eax, [esp+8]	; ExceptionRecord
		mov	edi, [esp+0x10] ; ContextRecord

		push	0x55; local-enable DR0, DR1, DR2, DR3 - how does it actually happen? didnt understand this 0x55
		pop	ecx
		inc	dword [ecx*2+edi+0x0e]; EIP (which is defined in ContextRecord) - why does not use AA instead of 55*2
					      ; Debugging I did not see EIP being incremented... bug?
					      ; that's EIP in CONTEXT, skip one NOP at each time

		mov	eax, [eax]; ExceptionCode
		sub	eax, 0x80000003
		jne	.test_singlestep ; if code is not EXCEPTION_BREAKPOINT (usual) jumps to .test_singlestep
		mov	eax, .labelone	 ; EAX has offset of .labelone
		scasd
		stosd	; dr0
		inc	eax
		stosd	; dr1
		inc	eax
		stosd	; dr2
		inc	eax
		stosd	; dr3
		mov	ch,1
		xchg	ecx, eax
		scasd
		stosd	; dr7 ?
		xor	eax,eax
		pop	edi
		ret

	.test_singlestep:
		dec	eax;
		jne	.being_debugged ; if ExceptionCode is equal SINGLE_STEP 0x80000002 then debugger detected
					; otherwise return
		inc	dword [ecx*2+edi+6]; EAX increment EAX in the CONTEXT, used to hold the count of single-step instructions!
		pop	edi
		ret

	.being_debugged:
		invoke	MessageBox,HWND_DESKTOP,"Debugger Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0
	.exit:
		invoke	MessageBox,HWND_DESKTOP,"Debugger NOT Found!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess,0

  .end start
