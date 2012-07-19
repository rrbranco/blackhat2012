#include "windows.h"

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _DEBUG_BUFFER {
	HANDLE SectionHandle;
	PVOID  SectionBase;
	PVOID  RemoteSectionBase;
	ULONG  SectionBaseDelta;
	HANDLE  EventPairHandle;
	ULONG  Unknown[2];
	HANDLE  RemoteThreadHandle;
	ULONG  InfoClassMask;
	ULONG  SizeOfInfo;
	ULONG  AllocatedSize;
	ULONG  SectionSize;
	PVOID  ModuleInformation;
	PVOID  BackTraceInformation;
	PVOID  HeapInformation;
	PVOID  LockInformation;
	PVOID  Reserved[8];
} DEBUG_BUFFER, *PDEBUG_BUFFER;

typedef struct _DEBUG_HEAP_INFORMATION
{
	ULONG Base; // 0×00
	ULONG Flags; // 0×04
	USHORT Granularity; // 0×08
	USHORT Unknown; // 0x0A
	ULONG Allocated; // 0x0C
	ULONG Committed; // 0×10
	ULONG TagCount; // 0×14
	ULONG BlockCount; // 0×18
	ULONG Reserved[7]; // 0x1C
	PVOID Tags; // 0×38
	PVOID Blocks; // 0x3C
} DEBUG_HEAP_INFORMATION, *PDEBUG_HEAP_INFORMATION;

// RtlQueryProcessDebugInformation.DebugInfoClassMask constants
#define PDI_MODULES                       0x01
#define PDI_BACKTRACE                     0x02
#define PDI_HEAPS                         0x04
#define PDI_HEAP_TAGS                     0x08
#define PDI_HEAP_BLOCKS                   0x10
#define PDI_LOCKS                         0x20

#ifdef __cplusplus
extern "C" {  
#endif  

extern "C" __declspec(dllimport) NTSTATUS __stdcall RtlQueryProcessDebugInformation(
	IN ULONG  ProcessId,
	IN ULONG  DebugInfoClassMask,
	IN OUT PDEBUG_BUFFER  DebugBuffer);

extern "C" __declspec(dllimport) PDEBUG_BUFFER __stdcall RtlCreateQueryDebugBuffer(
	IN ULONG  Size,
	IN BOOLEAN  EventPair);

extern "C" __declspec(dllimport) NTSTATUS __stdcall RtlDestroyQueryDebugBuffer(
IN PDEBUG_BUFFER  DebugBuffer);

extern "C" __declspec(dllimport) NTSTATUS __stdcall RtlQueryProcessHeapInformation(
	IN PDEBUG_BUFFER  DebugBuffer
);

#ifdef __cplusplus
}
#endif