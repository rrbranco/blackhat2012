; Created for Hackers 2 Hackers Conference (H2HC) 2012 - 9th Edition
; Training: Windows Malware Reverse Engineering
;
; Authors:
; Rodrigo Rubira Branco
; Gabriel Negreira Barbosa
;
; VMWare IN Anti-VM Technique
;
; Based on:
; Tom Liston, and Ed Skoudis - On the Cutting Edge: Thwarting Virtual Machine Detection - http://handlers.sans.org/tliston/ThwartingVMDetection_Liston_Skoudis.pdf

include 'win32ax.inc'

.code

  start:
	push	.vmware_not_detected
	push	dword [fs:0x0]
	mov	[fs:0x0],esp

	mov	eax,0x564D5868 ; 'VMXh'
	mov	ebx,0x0
	mov	ecx,0xA
	mov	edx,0x5658 ; 'VX'

	in	eax,dx

	cmp	ebx,0x564D5868 ; 'VMXh'
	je	.vmware_detected
	jmp	.vmware_not_detected



	.vmware_detected:
		invoke	MessageBox,HWND_DESKTOP,"VMWare Detected!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess, 0

	.vmware_not_detected:
		invoke	MessageBox,HWND_DESKTOP,"VMWare NOT Detected!",invoke GetCommandLine,MB_OK
		invoke	ExitProcess, 0

  .end start
