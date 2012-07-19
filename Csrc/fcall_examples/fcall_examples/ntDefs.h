#include "windows.h"
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#ifdef __cplusplus
extern "C" {  
#endif 
extern "C"
__declspec(dllimport) 
ULONG __stdcall 
NtSetDebugFilterState(
					 ULONG ComponentId,
					 ULONG Level,
					 BOOLEAN State					 
					 );
#ifdef __cplusplus
}
#endif