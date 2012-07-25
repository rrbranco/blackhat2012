// VMDetection.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <conio.h>

// 5.1
// Reference:
// ScoopyNG - The VMware detection tool - Version v1.0 - Tobias Klein, 2008 - www.trapkit.de

void fsidt() {
	unsigned char	idtr[6];
	unsigned long	idt	= 0;

	_asm sidt idtr
	idt = *((unsigned long *)&idtr[2]);

	if 	((idt >> 24) == 0xff)
		printf ("VMware detected\n");
}

void fsldt() {
	unsigned char   ldtr[5] = "\xef\xbe\xad\xde";
	unsigned long   ldt			= 0;

	_asm sldt ldtr
	ldt = *((unsigned long *)&ldtr[0]);

	if (ldt == 0xdead0000)
		printf ("Native OS\n");
	else
		printf ("VMware detected\n");
}

void fsgdt() {
	unsigned char   gdtr[6];
	unsigned long   gdt	= 0;

	_asm sgdt gdtr
	gdt = *((unsigned long *)&gdtr[2]);

	if ((gdt >> 24) == 0xff)
		printf ("VMware detected\n");
}

void fstr() {
	unsigned char	mem[4] = {0, 0, 0, 0};

	__asm str mem;

	if ((mem[0] == 0x00) && (mem[1] == 0x40))
		printf ("VMware detected\n");
	else
		printf ("Native OS\n");
}

// reference: http://www.offensivecomputing.net/ Written by Danny Quist, Offensive Computing

void fsmsw() {
    unsigned int reax = 0;

    __asm
    {
        mov eax, 0xCCCCCCCC;
        smsw eax;
        mov DWORD PTR [reax], eax;
    }

	if ( (( (reax >> 24) & 0xFF ) == 0xcc) && (( (reax >> 16) & 0xFF ) == 0xcc))
        printf("VMWare detected\n");
}

// 5.2
// Reference: ScoopyNG - The VMware detection tool - Version v1.0 - Tobias Klein, 2008 - www.trapkit.de
void fin() {
	unsigned int	a	= 0;

	__try {
		__asm {

			// save register values on the stack
			push eax
			push ebx
			push ecx
			push edx
			
			// perform fingerprint
			mov eax, 'VMXh'		// VMware magic value (0x564D5868)
			mov ecx, 14h		// get memory size command (0x14)
			mov dx, 'VX'		// special VMware I/O port (0x5658)
			
			in eax, dx			// special I/O cmd
			
			mov a, eax			// data 

			// restore register values from the stack
			pop edx
			pop ecx
			pop ebx
			pop eax
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {}

	printf ("\n[+] Test 6: VMware \"get memory size\" command\n");
	
	if (a > 0)
		printf ("Result  : VMware detected\n\n");
	else 
		printf ("Result  : Native OS\n\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
	//fsidt();
	//fsgdt();
	//fsldt();
	//fstr();
	//fsmsw();
	

	_getch();
	return 0;
}

