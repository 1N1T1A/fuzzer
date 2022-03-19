#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <wdmguid.h>
#include <ntddkbd.h>
#include "Header.h"
#include <tchar.h>
#include <strsafe.h>
#include <conio.h>
#include <cstring>
#include <string.h>
#include "Header.h"



using namespace std;
#ifdef __cplusplus
extern "C" {
#endif
	NTSTATUS ntsyscallgate(ULONG sid, ULONG paramcount, ULONG_PTR *args); 
#ifdef __cplusplus
}
#endif
typedef long long ptr;
typedef NTSTATUS(NTAPI* structptr)
(ptr,ptr,ptr,ptr,ptr,ptr,ptr,ptr);

#define MAX_SIZE 16000
typedef char* (__stdcall *syscallname)();
typedef char* (__stdcall *syscallname1)(char *);
typedef char* (__fastcall *syscallname2)(char *, char *);
typedef char* (__stdcall *syscallname3)(char *, char *, char *);
typedef char* (__fastcall *syscallname4)(char *, char *, char *,char *);
typedef char* (__fastcall *syscallname5)(char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname6)(char *, char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname7)(char *, char *,  char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname8)(char *, char *, char *, char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname9)(char *, char *, char *, char *, char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname10)(char *, char *, char *, char *, char *, char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname11)(char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *);
typedef char* (__fastcall *syscallname12)(char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname13)(char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname14)(char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname15)(char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *);
typedef char* (__stdcall *syscallname16)(char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *, char *);

static const ULONG_PTR fuzzdata[13] = {
	-0x0000000000000001, 0x000000000000ffff, 0x000000000000fffe, 0x00007ffffffeffff,
	0x00007ffffffefffe, 0x00007fffffffffff, 0x00007ffffffffffe, 0x0000800000000000,
	0x8000000000000000, 0xffff080000000000, 0xfffff80000000000, 0xffff800000000000,
	0xffff800000000001
};


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
#define BUF_SIZE 255
typedef struct syscall
{
	BYTE parameter;
	BYTE syscallid;
	CHAR syscallname;
	int argcount;
};
BYTE KernelParameters[211] = {
	0x18,0x20,0x2C,0x08,0x18,0x18,0x08,0x04,0x04,0x0c,\
	0x18,0x0c,0x08,0x08,0x04,0x04,0x0c,0x04,0x20,0x08,\
	0x0c,0x14,0x0c,0x2C,0x10,0x1C,0x20,0x10,0x38,0x10,\
	0x14,0x20,0x24,0x1C,0x14,0x10,0x20,0x10,0x34,0x08,\
	0x04,0x04,0x04,0x0c,0x08,0x28,0x04,0x1c,0x18,0x18,\
	0x18,0x08,0x08,0x08,0x0c,0x04,0x10,0x00,0x10,0x28,\
	0x08,0x10,0x00,0x08,0x0C,0x04,0x08,0x04,0x08,0x0C,\
	0x28,0x10,0x04,0x28,0x24,0x28,0x0c,0x0c,0x0c,0x18,\
	0x0c,0x0c,0x0c,0x30,0x10,0x0c,0x0c,0x0c,0x0c,0x10,\
	0x10,0x0C,0x10,0x0C,0x14,0x18,0x14,0x08,0x14,0x08,\
	0x08,0x2c,0x1C,0x24,0x14,0x08,0x14,0x14,0x14,0x14,\
	0x14,0x14,0x08,0x14,0x18,0x14,0x14,0x2C,0x08,0x14,\
	0x14,0x14,0x0C,0x10,0x10,0x04,0x14,0x0C,0x18,0x18,\
	0x14,0x14,0x0C,0x18,0x24,0x18,0x14,0x04,0x08,0x0C,\
	0x14,0x0C,0x08,0x10,0x08,0x08,0x0C,0x08,0x0C,0x08,\
	0x08,0x14,0x08,0x04,0x08,0x10,0x08,0x04,0x04,0x00,\
	0x14,0x10,0x10,0x10,0x10,0x10,0x08,0x18,0x04,0x04,\
	0x00,0x0c,0x08,0x0C,0x0c,0x08,0x1C,0x0C,0x18,0x14,\
	0x04,0x10,0x04,0x04,0x08,0x18,0x08,0x08,0x00,0x04,\
	0x04,0x14,0x10,0x08,0x08,0x14,0x0C,0x04,0x04,0x24,\
	0x24,0x18,0x14,0x14,0x08,0x08,0x08,0x0C,0x10,0x04,\
	0x00 };

BYTE serviceid[453] = { 0x0060,0x0061,0x0026,0x0062,0x0056,0x0063,0x0064,0x0065,\
0x0044,0x0066,0x0067,0x0068,0x003e,0x0069,0x006a,0x006b,\
0x006c,0x006d,0x006e,0x0015,0x006f,0x0070,0x0071,0x0072,\
0x0073,0x0074,0x0075,0x0076,0x0077,0x0078,0x0079,0x007a,\
0x007b,0x007c,0x007d,0x007e,0x007f,0x0080,0x0081,0x0082,\
0x0083,0x0049,0x0084,0x0085,0x0002,0x005a,0x0086,0x0087,\
0x005e,0x003b,0x000c,0x0038,0x0088,0x0089,0x008a,0x008c,\
0x008d,0x008e,0x008f,0x0040,0x0090,0x0091,0x0092,0x0045,\
0x0093,0x0052,0x0094,0x0095,0x0096,0x001a,0x0097,0x0098,\
0x0099,0x009a,0x009b,0x009b,0x009c,0x009d,0x009e,0x009f,\
0x004a,0x00a0,0x00a1,0x00a2,0x0047,0x00a3,0x00a4,0x004b,\
0x00a5,0x00a6,0x00a7,0x00a8,0x00a9,0x00aa,0x00ab,0x00ac,\
0x00ad,0x00ae,0x0031,0x00af,0x00b0,0x00b1,0x00b2,0x00b3,\
0x00b4,0x00b5,0x00b6,0x0004,0x00b7,0x00b8,0x00b9,0x0039,\
0x003f,0x00ba,0x00bb,0x00bc,0x002f,0x00bd,0x00be,0x0010,\
0x00bf,0x00c0,0x0011,0x0048,0x00c1,0x00c2,0x00c3,0x00c4,\
0x00c5,0x00c6,0x00c7,0x001b,0x00c8,0x00c9,0x0036,0x00ca,\
0x00cb,0x00cc,0x00cd,0x00ce,0x00cf,0x00d0,0x00d1,0x00d2,\
0x00d3,0x00d4,0x001c,0x00d5,0x00d6,0x00d7,0x00d8,0x004c,\
0x00d9,0x00da,0x00db,0x00dc,0x00dd,0x00de,0x00df,0x00e0,\
0x00e1,0x00e2,0x00e3,0x00e4,0x00e5,0x00e6,0x00e7,0x0000,\
0x0025,0x00e8,0x00e9,0x00ea,0x00eb,0x00ec,0x00ed,0x0055,\
0x00ee,0x003d,0x00ef,0x0030,0x00f0,0x00f1,0x000f,0x00f2,\
0x00f3,0x00f4,0x00f5,0x00f6,0x00f7,0x00f8,0x0023,0x00f9,\
0x002d,0x00fa,0x0034,0x00fb,0x00fc,0x00fd,0x00fe,0x0021,\
0x002c,0x00ff,0x0100,0x0101,0x0102,0x005c,0x0103,0x0104,\
0x0105,0x0106,0x0107,0x0108,0x0109,0x010a,0x010b,0x004d,\
0x010c,0x003a,0x010d,0x010e,0x010f,0x0012,0x0041,0x0032,\
0x0110,0x0111,0x0112,0x0053,0x0113,0x0114,0x0115,0x000e,\
0x0116,0x0117,0x0118,0x0022,0x001e,0x0119,0x011a,0x011b,\
0x011c,0x011d,0x011e,0x0013,0x011f,0x0120,0x0121,0x000d,\
0x0122,0x0123,0x002e,0x0124,0x0125,0x004e,0x0126,0x0127,\
0x0128,0x0129,0x012a,0x012b,0x0033,0x012c,0x0057,0x0035,\
0x012d,0x0014,0x0020,0x0046,0x0042,0x012e,0x012f,0x0130,\
0x0003,0x002b,0x0131,0x0051,0x003c,0x0132,0x0133,0x0134,\
0x0135,0x0136,0x0137,0x001d,0x0007,0x0138,0x0006,0x0139,\
0x013a,0x013b,0x013c,0x013d,0x013e,0x0009,0x0008,0x0028,\
0x013f,0x0140,0x001f,0x0141,0x0142,0x0143,0x0144,0x004f,\
0x0145,0x0146,0x0147,0x0148,0x0149,0x014a,0x014b,0x014c,\
0x014d,0x014e,0x014f,0x0150,0x0151,0x0152,0x0153,0x0154,\
0x0155,0x0156,0x000b,0x002a,0x0157,0x0158,0x0159,0x015a,\
0x0024,0x015b,0x015c,0x0059,0x0019,0x015d,0x000a,0x015e,\
0x015f,0x0160,0x0161,0x0162,0x0163,0x0164,0x0165,0x0166,\
0x0167,0x0168,0x0169,0x016a,0x016b,0x016c,0x016d,0x016e,\
0x016f,0x005f,0x0170,0x0171,0x0172,0x005d,0x0173,0x0174,\
0x0175,0x0176,0x0177,0x0178,0x0179,0x017a,0x017b,0x017c,\
0x017d,0x0029,0x0050,0x017e,0x017f,0x0180,0x0181,0x005b,\
0x0182,0x0183,0x0184,0x0185,0x0186,0x0187,0x0188,0x0189,\
0x0027,0x018a,0x018b,0x018c,0x0058,0x0017,0x0001,0x018d,\
0x018e,0x018f,0x0190,0x0005,0x0018,0x0054,0x0037,0x0043 };


ULONG na[] = { 6,8,11,11,16,11,16,17,0,3,4,2,2,6,6,16,2,1,\
8, 4, 3, 2, 3, 3, 2, 2, 2 , 1, 0, 1, 3, 2, 2, 2, 2, 3, 1, 1, 8, 2, 4, 3, 5, 9, 8, 3, 0, 2, 4, 3, 3, 8, 4, 9, 8, 4, 14, 4, 4, 5, 4, 8, 9, 9, 10, 4, 7, 5, 4, 10, 11, 4, 13, 14, 10, 6, 11, 5, 10,\
3,3,4,6,9,3,\
11,3,6,4,3,3,3,3,3,3,2,3,6,6,5,6,3,8,4,2,2,3,2,\
3,3,2,1,1,3,2,2,2,2,3,1,1,8,2,4,3,8,5,3,11,4,3,\
3,7,8,4,8,4,14,4,5,4,8,9,9,10,7,5,4,8,11,4,13,10,\
6,11,5,10,2,3,2,1,1,1,1,1,3,1,2,10,0,1,1,7,6,0,2,\
2,6,3,5,6,2,6,3,2,2,3,1,0,4,0,3,4,1,2,10,2,0,2,3,\
5,6,5,7,0,7,1,2,3,3,1,4,2,0,0,2,1,2,3,8,10,2,1,4,\
1,1,6,3,3,10,1,9,10,12,8,3,5,3,3,6,3,3,3,3,4,5,3,3,\
12,4,4,3,4,5,3,3,3,3,4,4,5,3,5,6,3,5,2,2,2,2,3,6,5,4,\
3,5,2,2,2,2,2,2,1,11,7,2,9,5,2,5,5,5,5,5,5,5,5,5,5,5,\
1,2,5,5,6,5,5,2,4,2,0,9,5,6,5,5,3,4,5,4,6,1,5,3,6,6,5,\
5,6,3,6,9,9,2,6,5,2,1,1,5,1,4,2,3,1,5,6,2,2,2,3,3,2,4,5,\
4,5,2,2,3,2,3,3,1,2,2,2,2,2,2,3,3,9,0,2,2,2,3,1,2,1,2,4,\
2,1,1,1,5,4,5,4,4,4,4,4,4,4,4,4,2,5,6,6,1,1,4,2,5,3,3,2,\
2,7,4,3,1,1,2,4,2,1,1,1,2,6,2,2,2,0,0,6,4,4,1,1,1,2,2,5,\
4,2,4,4,5,3,2,1,1,9,6,5,0 };

void kernelbase(LPVOID p);


typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
	ULONG                Reserved3;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 LoadCount;
	WORD                 NameOffset;
	CHAR                 Name[256];
}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 11,
	SystemProcessInformation=5
}SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI* nNtQuerySystemInformation)
(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG length,
	__out_opt PULONG ReturnLength);

typedef NTSTATUS(NTAPI* nNtClose)
(HANDLE      ProcessHandle
	);

typedef NTSTATUS(NTAPI* nNtOpenProcessToken)
(HANDLE      ProcessHandle,
	ACCESS_MASK DesiredAccess,
	
	PHANDLE     TokenHandle);
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	//KPRIORITY Priority;
	//KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	//THREAD_STATE State;
	//KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_PROCESSES_INFORMATION {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESSES_INFORMATION, *PSYSTEM_PROCESSES_INFORMATION;

//#include <winternl.h>

typedef VOID(NTAPI* rRtlInitUnicodeString)(
	PUNICODE_STRING         DestinationString,
	 PCWSTR SourceString);

typedef BOOLEAN(NTAPI* rRtlEqualUnicodeString)(
	PUNICODE_STRING         DestinationString,
	PUNICODE_STRING  SourceString,
	BOOLEAN          CaseInSensitive);


typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* nNtDuplicateToken)
(HANDLE             ExistingTokenHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN            EffectiveOnly,
	TOKEN_TYPE         TokenType,
	PHANDLE            NewTokenHandle);

typedef NTSTATUS(NTAPI* nNtAdjustPrivilegesToken)
(IN HANDLE               TokenHandle,
	IN BOOLEAN              DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES    TokenPrivileges,
	IN ULONG                PreviousPrivilegesLength,
	OUT PTOKEN_PRIVILEGES   PreviousPrivileges OPTIONAL,
	OUT PULONG              RequiredLength OPTIONAL
);

typedef struct Ps
{
	ULONG privilege;

}Ps, *PS;

typedef NTSTATUS(NTAPI* nNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);
typedef	NTSTATUS(NTAPI* nNtSetInformationToken)(
	HANDLE                  TokenHandle,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID                   TokenInformation,
	ULONG                   TokenInformationLength
);
#ifndef RTL_CONSTANT_STRING
char _RTL_CONSTANT_STRING_type_check(const void *s);
#define _RTL_CONSTANT_STRING_remove_const_macro(s) (s)
#define RTL_CONSTANT_STRING(s) \
{ \
    sizeof( s ) - sizeof( (s)[0] ), \
    sizeof( s ) / sizeof(_RTL_CONSTANT_STRING_type_check(s)), \
    _RTL_CONSTANT_STRING_remove_const_macro(s) \
}
#endif
typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	
	
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];

	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, *PPEB;
typedef struct _TEB {
	PVOID Reserved1[12];
	PPEB  ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE  Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE  Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, *PTEB;

#define NtCurrentPeb()	   (NtCurrentTeb()->ProcessEnvironmentBlock)

/*PEB *NtCurrentPeb(VOID)
{
	return (PEB *)__readfsdword(FIELD_OFFSET(TEB, ProcessEnvironmentBlock));
}*/
/*
PS privileges[]=
{ SE_CREATE_TOKEN_PRIVILEGE ,
 SE_ASSIGNPRIMARYTOKEN_PRIVILEGE ,
 SE_LOCK_MEMORY_PRIVILEGE,
 SE_INCREASE_QUOTA_PRIVILEGE,
 SE_MACHINE_ACCOUNT_PRIVILEGE,
 SE_TCB_PRIVILEGE, 
 SE_SECURITY_PRIVILEGE, 
 SE_TAKE_OWNERSHIP_PRIVILEGE,
 SE_LOAD_DRIVER_PRIVILEGE, 
 SE_SYSTEM_PROFILE_PRIVILEGE, 
 SE_SYSTEMTIME_PRIVILEGE, 
 SE_PROF_SINGLE_PROCESS_PRIVILEGE, 
 SE_INC_BASE_PRIORITY_PRIVILEGE, 
 SE_CREATE_PAGEFILE_PRIVILEGE, 
 SE_CREATE_PERMANENT_PRIVILEGE, 
 SE_BACKUP_PRIVILEGE, 
 SE_RESTORE_PRIVILEGE, 
 SE_SHUTDOWN_PRIVILEGE,
 SE_DEBUG_PRIVILEGE, 
 SE_AUDIT_PRIVILEGE, 
 SE_SYSTEM_ENVIRONMENT_PRIVILEGE, 
 SE_CHANGE_NOTIFY_PRIVILEGE, 
 SE_REMOTE_SHUTDOWN_PRIVILEGE, 
 SE_UNDOCK_PRIVILEGE,
 SE_SYNC_AGENT_PRIVILEGE, 
 SE_ENABLE_DELEGATION_PRIVILEGE, 
 SE_MANAGE_VOLUME_PRIVILEGE, 
 SE_IMPERSONATE_PRIVILEGE, 
 SE_CREATE_GLOBAL_PRIVILEGE, 
 SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE, 
 SE_RELABEL_PRIVILEGE, 
 SE_INC_WORKING_SET_PRIVILEGE, 
 SE_TIME_ZONE_PRIVILEGE, 
 SE_CREATE_SYMBOLIC_LINK_PRIVILEGE
};
*/

typedef VOID(NTAPI* iInitializeObjectAttributes)(
	          POBJECT_ATTRIBUTES   p,
	          PUNICODE_STRING      n,
	           ULONG                a,
	           HANDLE               r,
	 PSECURITY_DESCRIPTOR s
);
typedef NTSTATUS(NTAPI* nNtDuplicateToken)(
	HANDLE             ExistingTokenHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN            EffectiveOnly,
	TOKEN_TYPE         TokenType,
	PHANDLE            NewTokenHandle
);

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
	ThreadTimes, // q: KERNEL_USER_TIMES
	ThreadPriority, // s: KPRIORITY
	ThreadBasePriority, // s: LONG
	ThreadAffinityMask, // s: KAFFINITY
	ThreadImpersonationToken, // s: HANDLE
	ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
	ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress, // q: PVOID
	ThreadZeroTlsCell, // 10
	ThreadPerformanceCount, // q: LARGE_INTEGER
	ThreadAmILastThread, // q: ULONG
	ThreadIdealProcessor, // s: ULONG
	ThreadPriorityBoost, // qs: ULONG
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending, // q: ULONG
	ThreadHideFromDebugger, // s: void
	ThreadBreakOnTermination, // qs: ULONG
	ThreadSwitchLegacyState,
	ThreadIsTerminated, // q: ULONG // 20
	ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
	ThreadIoPriority, // qs: IO_PRIORITY_HINT
	ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
	ThreadPagePriority, // q: ULONG
	ThreadActualBasePriority,
	ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
	ThreadCSwitchMon,
	ThreadCSwitchPmu,
	ThreadWow64Context, // q: WOW64_CONTEXT
	ThreadGroupInformation, // q: GROUP_AFFINITY // 30
	ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
	ThreadCounterProfiling,
	ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
	ThreadCpuAccountingInformation, // since WIN8
	ThreadSuspendCount, // since WINBLUE
	ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
	ThreadContainerId, // q: GUID
	ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
	ThreadSelectedCpuSets,
	ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
	ThreadActualGroupAffinity, // since THRESHOLD2
	ThreadDynamicCodePolicyInfo,
	ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
	ThreadWorkOnBehalfTicket,
	ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ThreadDbgkWerReportActive,
	ThreadAttachContainer,
	ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ThreadPowerThrottlingState, // THREAD_POWER_THROTTLING_STATE
	ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
	MaxThreadInfoClass
} THREADINFOCLASS;


typedef NTSTATUS(NTAPI* nNtSetInformationThread)(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength
);
typedef NTSTATUS(NTAPI* nNtCloseToken)(HANDLE token);

int console();
BOOL adminornot();
int enable_privs(LPCSTR privilege);
int closetoken(HANDLE token);
NTSTATUS executer(char *syscalname, int n,int s);
VOID system1();
NTSTATUS goroot(PHANDLE systemtoken);
NTSTATUS win32kexecuter(char *syscalname, int n, int s);
int kurt();
int main()
{
	while (1)
	{
		
		kurt();
	}
}
int kurt()
{
	system("color 0A");
	//kernelbase(0);
	//printf("serviceid     syscall  \t\t             parameter\n\n");
	
	enable_privs((LPCSTR)SE_INCREASE_QUOTA_NAME);
	enable_privs((LPCSTR)SE_DEBUG_NAME);
	while (1)
	{
		for (int j = 0; j < 10; j++)
		{
			//int r = rand() % 400;
			for (int i = 0; i < 200; i++)
			{
				int r = rand() % 200;
				//printf("%#x      %s        \t\t  %#x\n", serviceid[r], W32pServiceTableNames_7601[r], KernelParameters[r]);
				if (!executer(W32pServiceTableNames_7601[r], na[r], serviceid[r]))
				{
					printf("-----------------------------------------------------------------\n" );
					//return -1;
				}
				/*if (!win32kexecuter(win32ksys[r], na[r], serviceid[r]))
				{
					printf("------------------------------------------\n");
					//return -1;
				}*/
			}
		}
	}
	
		
		//system1();
		//ntsyscallgate(0, 0, 0);
	//console();
		if (adminornot())
		{
			printf("[+] User is admin \n");
		}
		else
		{
			printf("[-] User is not admin !\n");
		}
	system("pause");
	return 0;
}

void kernelbase(LPVOID p)
{
	nNtQuerySystemInformation NtQuerySystemInformation = (nNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	
	if (!NtQuerySystemInformation)
	{
		printf("Unable to find NtQueryInformationProcess %d\n", GetLastError());
	

	}

	NTSTATUS status;
	PSYSTEM_MODULE_INFORMATION buffer;
	ULONG len=0xffffff;
	//NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);

	buffer = (PSYSTEM_MODULE_INFORMATION)malloc(len);

	status = NtQuerySystemInformation(SystemModuleInformation, buffer, len, &len);

	if (!NT_SUCCESS(status))
	{
		printf("Unable to run NtQueryInformationProcess %d\n", GetLastError());
		//system("pause");
	}

	PVOID baseaddr;
	baseaddr = buffer->Modules[0].ImageBaseAddress;
	
		printf("[+]Leaking kernel (%s) base address  ", buffer->Modules[0].Name);
	printf(" 0x%p     \n", baseaddr);
	
}

int createthread()
{

	//HANDLE thread = CreateThread(NULL, 0, console, NULL, 0, NULL);
	return 0;
	//Create a process threasd with max privileges
}

NTSTATUS executer(char *syscalname, int n,int s)
{

	char *list[MAX_SIZE];
	int i;
	for (i = 0; i < MAX_SIZE; i++)
	{
		list[i]= (char *)0x0;
	}
	
		structptr handle = (structptr)GetProcAddress(GetModuleHandle(L"ntdll.dll"), syscalname);
		if (!handle)
		{
			// printf("[-]Unable to find syscall %d\n", GetLastError());
			return -1;
		}
	
	char *param[100];
	param[0] = (char *)0x1234567812345678;
	for (i = 0; i < 20; i++)
	{
		param[i] = (char *)fuzzdata[i];
	}

	
		printf(" syscall %s exec service id %#x param %#3x \n", syscalname, s, n);
		try {
			switch (n)
			{
			case 0:
				((syscallname)handle)();
				break;
			case 1:
				((syscallname1)handle)(param[0]);
				break;
			case 2:
				((syscallname2)handle)(param[0], param[1]);
				break;
			case 3:
				((syscallname3)handle)(param[0], param[1], param[2]);
				break;
			case 4:
				((syscallname4)handle)(param[0], param[1], param[3], param[4]);
				break;
			case 5:
				((syscallname5)handle)(param[0], param[1], param[2], param[3], param[4]);
				break;
			case 6:
				((syscallname6)handle)(param[0], param[1], param[2], param[3], param[4], param[5]);
				break;
			case 7:
				((syscallname7)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6]);
				break;
			case 8:
				((syscallname8)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7]);
				break;
			case 9:
				((syscallname9)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8]);
				break;
			case 10:
				((syscallname10)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9]);
				break;
			case 11:
				((syscallname11)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10]);
				break;
			case 12:
				((syscallname12)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11]);
				break;
			case 13:
				((syscallname13)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11], param[12]);
				break;
			case 14:
				((syscallname14)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11], param[12], param[13]);
				break;
			case 15:
				((syscallname15)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11], param[12], param[13], param[14]);
				break;
			case 16:
				((syscallname16)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11], param[12], param[13], param[14], param[15]);
				break;


			}
		}
		catch (...)
		{
			printf("[-] Exception occured!!\n");
		}
	
	return 0;
}

NTSTATUS win32kexecuter(char *syscalname, int n, int s)
{

	char *list[MAX_SIZE];
	int i;
	for (i = 0; i < MAX_SIZE; i++)
	{
		list[i] = (char *)0x0;
	}

	void* handle = (void *)GetProcAddress(GetModuleHandle(L"win32u.dll"), syscalname);
	if (!handle)
	{
		// printf("[-]Unable to find syscall %d\n", GetLastError());
		return -1;
	}

	char *param[100];
	param[0] = (char *)0x1234567812345678;
	for (i = 0; i < 20; i++)
	{
		param[i] = (char *)fuzzdata[i];
	}


	printf(" syscall %s exec service id %#x param %#3x \n", syscalname, s, n);
	try {
		switch (n)
		{
		case 0:
			((syscallname)handle)();
			break;
		case 1:
			((syscallname1)handle)(param[0]);
			break;
		case 2:
			((syscallname2)handle)(param[0], param[1]);
			break;
		case 3:
			((syscallname3)handle)(param[0], param[1], param[2]);
			break;
		case 4:
			((syscallname4)handle)(param[0], param[1], param[3], param[4]);
			break;
		case 5:
			((syscallname5)handle)(param[0], param[1], param[2], param[3], param[4]);
			break;
		case 6:
			((syscallname6)handle)(param[0], param[1], param[2], param[3], param[4], param[5]);
			break;
		case 7:
			((syscallname7)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6]);
			break;
		case 8:
			((syscallname8)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7]);
			break;
		case 9:
			((syscallname9)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8]);
			break;
		case 10:
			((syscallname10)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9]);
			break;
		case 11:
			((syscallname11)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10]);
			break;
		case 12:
			((syscallname12)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11]);
			break;
		case 13:
			((syscallname13)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11], param[12]);
			break;
		case 14:
			((syscallname14)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11], param[12], param[13]);
			break;
		case 15:
			((syscallname15)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11], param[12], param[13], param[14]);
			break;
		case 16:
			((syscallname16)handle)(param[0], param[1], param[2], param[3], param[4], param[5], param[6], param[7], param[8], param[9], param[10], param[11], param[12], param[13], param[14], param[15]);
			break;


		}
	}
	catch (...)
	{
		printf("[-] Exception occured!!\n");
	}

	return 0;
}
int crashlog()
{
	//record crash log
	return 0;
}

ULONG __readfsdword(ULONG Offset)
{
	return 0;
}

int console()
{
	HANDLE hStdout;
	

	TCHAR msgBuf[BUF_SIZE];
	size_t cchStringSize;
	DWORD dwChars;

	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdout == INVALID_HANDLE_VALUE)
		return 1;
	

	

	StringCchPrintf(msgBuf, BUF_SIZE, TEXT("Parameters = %d, %d\n"),
		4,5);
	StringCchLength(msgBuf, BUF_SIZE, &cchStringSize);
	WriteConsole(hStdout, msgBuf, (DWORD)cchStringSize, &dwChars, NULL);

	return 0;                         
	//create a console window for current process 
}

void checkprivs()
{
	//check if the usre is admin or not
	//if not provide most privileges
}

void closethreads()
{
	//close threads and freee multiple allocations
}

BOOL adminornot()
{

	//initialize sid to sid of nt authority
	//initialize the sid 
	//check if current process token is same as nt authority token
	//Return true is process is of admin group otherwise false
	SID_IDENTIFIER_AUTHORITY ntauth = SECURITY_NT_AUTHORITY;
	PSID adming;
	BOOL b = AllocateAndInitializeSid(
		&ntauth,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&adming);
	if (b)
	{
		if (!CheckTokenMembership(NULL,adming, &b))
		{
			b = FALSE;
		}
		FreeSid(adming);
	}

	return b;
}

int enable_privs(LPCSTR privilege)
{

	TOKEN_PRIVILEGES tokenpriv;
	NTSTATUS status;
	HANDLE  token = NULL;
	nNtOpenProcessToken NtOpenProcessToken = (nNtOpenProcessToken)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcessToken");
	nNtQuerySystemInformation NtQuerySystemInformation = (nNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	nNtAdjustPrivilegesToken NtAdjustPrivilegesToken = (nNtAdjustPrivilegesToken)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAdjustPrivilegesToken");
	if (!NtOpenProcessToken)
	{
		printf("[-]Unable to find NtOpenProcessToken %d\n", GetLastError());
		return -1;
	}
	//First part : Fin the access token of any system process
	ULONG len = 0xfffffff;
	PVOID buffer = malloc(len);
	status = NtQuerySystemInformation(SystemProcessInformation, buffer, len, &len);
	if (!NT_SUCCESS(status))
	{
		printf("[-]Unable to get process information\n");
		return -1;
	}
	
	//--------------------------------


	status=NtOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY|TOKEN_QUERY_SOURCE, &token);
	
	if (!NT_SUCCESS(status))
	{
		printf("[-]NtOpenProcessToken failed with error %d\n");
	}

	LUID uid;

	if (!LookupPrivilegeValue(NULL,(LPCWSTR)privilege, &uid))
	{
		printf("[-]Unable to get luid %d\n",GetLastError());
		//closetoken(token);
	}

	tokenpriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tokenpriv.Privileges[0].Luid =uid;
	tokenpriv.PrivilegeCount = 1;

	if (!NtAdjustPrivilegesToken)
	{
		printf("[-]Unable to get NtAdjsutPrivilegesToken %d\n", GetLastError());
	}

	NtAdjustPrivilegesToken(token, FALSE, &tokenpriv, sizeof(tokenpriv), NULL, 0);

	//closetoken(token);
	return 0;
}

void stackbuilder(int id, int args)
{
	
}

int closetoken(HANDLE token)
{
/*	nNtCloseToken NtClose = (nNtCloseToken)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtClose");
	if (!NtClose)
	{
		printf("[-]Unable to get NtClose \n",GetLastError());
		return -1;
	}
	NtClose(token);
	return 0;
	*/
	return 0;
}


NTSTATUS goroot(PHANDLE systemtoken)
{
	//execute atleast one thread of the process as local system
	TOKEN_PRIVILEGES token_privs;
	HANDLE t1;
	nNtOpenProcessToken NtOpenProcessToken = (nNtOpenProcessToken)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcessToken");
	nNtOpenProcess NtOpenProcess = (nNtOpenProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcess");
	NTSTATUS status;
	UNICODE_STRING win= RTL_CONSTANT_STRING(L"winlogon.exe");
	rRtlEqualUnicodeString RtlEqualUnicodeString = (rRtlEqualUnicodeString)GetProcAddress(GetModuleHandle(L"NtosKrnl.exe"), "RtlEqualUnicodeString");
	rRtlInitUnicodeString RtlInitUnicodeString= (rRtlInitUnicodeString)GetProcAddress(GetModuleHandle(L"NtosKrnl.exe"), "RtlInitUnicodeString");
	nNtQuerySystemInformation NtQuerySystemInformation = (nNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	nNtClose NtClose = (nNtClose)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtClose");
	/*if (!OpenProcessToken(GetCurrentProcess(), PROCESS_QUERY_INFORMATION, &t1))
	{
		printf("[-]Unable to get current process token\n");
		return -1;
	}*/
	if (!RtlInitUnicodeString)
	{
		printf("[-]Unable to get RtlInitUnicodeString\n");
		return -1;
	}
	if (!RtlEqualUnicodeString)
	{
		printf("[-]Unable to get RtlEqualUnicodeString\n");
		return -1;
	}
	ULONG len = 0xfffffff;
	PVOID buffer = malloc(len);
	status = NtQuerySystemInformation(SystemProcessInformation, buffer, len, &len);
	if (!NT_SUCCESS(status))
	{
		printf("[-]Unable to get process information\n");
		return -1;
	}
	PBYTE c;
	ULONG d;
	PSYSTEM_PROCESSES_INFORMATION process;
	DWORD sid = WTSGetActiveConsoleSessionId();
	HANDLE hObject = NULL;
	HANDLE hToken = NULL;
	*systemtoken = NULL;
	
	OBJECT_ATTRIBUTES objectattributes;
	CLIENT_ID cid;
	cid.UniqueProcess = process->UniqueProcessId;
	cid.UniqueThread = NULL;
	c = (PBYTE)buffer;
	while (d)
	{
		c = c+d;
		if(RtlEqualUnicodeString(&win,&process->ImageName,TRUE))
		{ 
			if (sid == process->SessionId)
			{
				status=NtOpenProcess(&hObject,PROCESS_QUERY_LIMITED_INFORMATION,&objectattributes,&cid);
				if (NT_SUCCESS(status))
				{
					status = NtOpenProcessToken(
						hObject,
						TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE | TOKEN_QUERY,
						&hToken);


					if (NT_SUCCESS(status))
					{
						//IsLocalSystem
						if(adminornot())
						{

							BOOL result=enable_privs("SeTcbPrivilege");
							if (result)
							{

								NtClose(hObject);
								*systemtoken = hToken;
								return 0;
							
							}
							else
							{
								printf("Unable \n", GetLastError());
								return -1;
							}
						}
						NtClose(hToken);
					}
					NtClose(hObject);
				}

			}

		}
		d = process->NextEntryDelta;
	}
	
	return status;
	
}

void privilegecheck(WCHAR* privilege)
{
	//Check if the current process has the input privilege!!Just for fun !!
}

//#include <winternl.h>
#include <malloc.h>
VOID system1()
{
	nNtOpenProcessToken NtOpenProcessToken = (nNtOpenProcessToken)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcessToken");
	nNtOpenProcess NtOpenProcess = (nNtOpenProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenProcess");
	NTSTATUS status;
	UNICODE_STRING win = RTL_CONSTANT_STRING(L"winlogon.exe");
	nNtAdjustPrivilegesToken NtAdjustPrivilegesToken = (nNtAdjustPrivilegesToken)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAdjustPrivilegesToken");
	rRtlEqualUnicodeString RtlEqualUnicodeString = (rRtlEqualUnicodeString)GetProcAddress(GetModuleHandle(L"NtosKrnl.exe"), "RtlEqualUnicodeString");
	rRtlInitUnicodeString RtlInitUnicodeString = (rRtlInitUnicodeString)GetProcAddress(GetModuleHandle(L"NtosKrnl.exe"), "RtlInitUnicodeString");
	nNtQuerySystemInformation NtQuerySystemInformation = (nNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	nNtSetInformationThread NtSetInformationThread = (nNtSetInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtSetInformationThread");
	nNtDuplicateToken NtDuplicateToken = (nNtDuplicateToken)GetProcAddress(GetModuleHandle(L"ntdll"), "NtDuplicateToken");
	
	nNtSetInformationToken NtSetInformationToken = (nNtSetInformationToken)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtSetInformationToken"); 
	iInitializeObjectAttributes InitializeObjectAttributes = (iInitializeObjectAttributes)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "InitializeObjectAttributes");
	nNtClose NtClose = (nNtClose)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtClose");
	BOOL bSuccess = FALSE;
	NTSTATUS Status;
	PVOID ProcessList;
	ULONG SessionId = NtCurrentPeb()->SessionId, dummy;

	HANDLE hSystemToken = NULL, hPrimaryToken = NULL, hImpersonationToken = NULL;

	BOOLEAN bThreadImpersonated = FALSE;

	PROCESS_INFORMATION pi;
	STARTUPINFO si;

	SECURITY_QUALITY_OF_SERVICE sqos;
	OBJECT_ATTRIBUTES obja;
	TOKEN_PRIVILEGES *TokenPrivileges;

	WCHAR szApplication[MAX_PATH * 2];

	//
	// Remember our application name.
	//
	RtlSecureZeroMemory(szApplication, sizeof(szApplication));
	GetModuleFileName(NULL, szApplication, MAX_PATH);
	
	sqos.Length = sizeof(sqos);
	sqos.ImpersonationLevel = SecurityImpersonation;
	sqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
	sqos.EffectiveOnly = FALSE;
	InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
	obja.SecurityQualityOfService = &sqos;
	ULONG len = 0xfffffff;
	PVOID buffer = malloc(len);
	status = NtQuerySystemInformation(SystemProcessInformation, buffer, len, &len);
	if (!NT_SUCCESS(status))
	{
		printf("[-]Unable to get process information\n");
		exit(0);
	}
	ProcessList = buffer;
	if (ProcessList == NULL) {
		return;
	}

	//
	// Optionally, enable debug privileges.
	// 
	enable_privs("SeDebugPrivilege");

	//
	// Get LocalSystem token from winlogon.
	//
	Status =goroot(&hSystemToken);

	

	do {
		//
		// Check supxGetSystemToken result.
		//
		if (!NT_SUCCESS(Status) || (hSystemToken == NULL)) {

			printf(	"No suitable system token found. Make sure you are running as administrator, code 0x",Status);

			break;
		}

		//
		// Duplicate as impersonation token.
		//
		Status = NtDuplicateToken(
			hSystemToken,
			TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY |
			TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES,
			&obja,
			FALSE,
			TokenImpersonation,
			&hImpersonationToken);

		if (!NT_SUCCESS(Status)) {

			printf("Error duplicating impersonation token, code 0x", Status);
			break;
		}

		//
		// Duplicate as primary token.
		//
		Status = NtDuplicateToken(
			hSystemToken,
			TOKEN_ALL_ACCESS,
			&obja,
			FALSE,
			TokenPrimary,
			&hPrimaryToken);

		if (!NT_SUCCESS(Status)) {

			printf("Error duplicating primary token, code 0x", Status);
			break;
		}

		
		// Impersonate system token.
		
		Status = NtSetInformationThread(
			GetCurrentThread(),
			ThreadImpersonationToken,
			&hImpersonationToken,
			sizeof(HANDLE));

		if (!NT_SUCCESS(Status)) {

			printf("Error while impersonating primary token, code 0x", Status);
			break;
		}

		bThreadImpersonated = TRUE;

		//
		// Turn on AssignPrimaryToken privilege in impersonated token.
		//
		TokenPrivileges = (TOKEN_PRIVILEGES*)_alloca(sizeof(TOKEN_PRIVILEGES) +
			(1 * sizeof(LUID_AND_ATTRIBUTES)));

		TokenPrivileges->PrivilegeCount = 1;
		TokenPrivileges->Privileges[0].Luid.LowPart = (DWORD)SE_ASSIGNPRIMARYTOKEN_NAME;
		TokenPrivileges->Privileges[0].Luid.HighPart = 0;
		TokenPrivileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		Status = NtAdjustPrivilegesToken(
			hImpersonationToken,
			FALSE,
			TokenPrivileges,
			0,
			NULL,
			(PULONG)&dummy);

		if (!NT_SUCCESS(Status)) {
		printf("Error adjusting token privileges, code 0x", Status);
			break;
		}

		//
		// Set session id to primary token.
		//
		Status = NtSetInformationToken(
			hPrimaryToken,
			TokenSessionId,
			&SessionId,
			sizeof(ULONG));

		if (!NT_SUCCESS(Status)) {
			printf("Error setting session id, code 0x", Status);
			break;
		}

		si.cb = sizeof(si);
		GetStartupInfo(&si);

		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_SHOWNORMAL;

		//
		// Run new instance with prepared primary token.
		//
		bSuccess = CreateProcessAsUser(
			hPrimaryToken,
			szApplication,
			GetCommandLine(),
			NULL,
			NULL,
			FALSE,
			CREATE_DEFAULT_ERROR_MODE,
			NULL,
			NULL,
			&si,
			&pi);

		if (bSuccess) {
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
		else {
			printf("Run as LocalSystem, code 0x", GetLastError());
		}

	} while (FALSE);

	if (hImpersonationToken) {
		NtClose(hImpersonationToken);
	}

	//
	// Revert To Self.
	//
	if (bThreadImpersonated) 
	{
		hImpersonationToken = NULL;
		NtSetInformationThread(
			GetCurrentThread(),
			ThreadImpersonationToken,
			(PVOID)&hImpersonationToken,
			sizeof(HANDLE));
	}

	if (hPrimaryToken) NtClose(hPrimaryToken);
	if (hSystemToken) NtClose(hSystemToken);

	//
	// Quit.
	//
	if (bSuccess)
		PostQuitMessage(0);

}