#ifndef __GDRIVER__
#define __GDRIVER__

#include "includes.h"

extern _NtQuerySystemTime pNtQuerySystemTime;
extern _NtQuerySystemInformation pNtQuerySystemInformation;
extern _NtOpenProcess pNtOpenProcess;
extern _NtTerminateProcess pNtTerminateProcess;
extern _NtDuplicateObject pNtDuplicateObject;
extern _NtQueryObject pNtQueryObject;
extern _NtClose pNtClose;

extern PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
extern PSYSTEM_SERVICE_TABLE g_pSSDT;
extern PSYSTEM_SERVICE_TABLE g_pSSDTS;

#endif