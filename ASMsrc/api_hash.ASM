; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
;
; This program was created only to test PEB-> Ldr Address Resolving detection (4.3)
; it is by no means a fully functional program to be used in order to import windows APIs
; reference: Harmony Security - Blog - Retrieving Kernel32's Base Address
; http://blog.harmonysecurity.com/2009/06/retrieving-kernel32s-base-address.html

include 'win32ax.inc'

.code

  start:
	pusha
	mov	eax,[fs:0x30]	; PEB
	mov	eax,[eax+0xc]	; Ldr
	mov	eax,[eax+0xc]	; InLoadOrderModuleList.Flink
	mov	eax,[eax]	; InLoadOrderModuleList.Flink
	mov	eax,[eax]	; InLoadOrderModuleList.Flink
	mov	eax,[eax+0x18]	; BaseAddress

	mov	ebx,eax

	add	eax,[eax+0x3c]	; DOS_HEADER.e_lfanew
	mov	eax,[eax+0x78]	; OptionalHeader.ExportDir.VirtualAddress
	add	eax,ebx

	lea	esi,[eax+0x1c]	 ; AddressOfFunctions

	invoke	ExitProcess,0

  .end start