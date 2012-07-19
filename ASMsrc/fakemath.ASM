; Qualys Vulnerabliity & Malware Research Labs (VMRL)
; Blackhat 2012 Presentation Samples
; TiTle:   A Scientific (but non academic) study of how malware employs anti-debugging,
;          anti-disassembly and anti-virtualization technologies
; Authors: Rodrigo Rubira Branco <rbranco *NOSPAM* qualys.com>
;          Gabriel Negreira Barbosa <gbarbosa *NOSPAM* qualys.com>
;          Pedro Drimel Neto <pdrimel *NOSPAM* qualys.com>
;
; This program was created to test push followed by pop and xor/or (4.1)
; reference: Laspe Raber, Jason Raber - BlackHat 2008
;            Deobfuscator: An Automated Approach to the Identification and Removal of Code Obfuscation


include 'win32ax.inc'

.code

  start:
	xor	eax,eax
	xor	ebx,ebx
	xor	ecx,ecx
	xor	edx,edx
	push	0x4040
	pop	eax
	xor	eax, 0x5050

	invoke	ExitProcess,0
  .end start
