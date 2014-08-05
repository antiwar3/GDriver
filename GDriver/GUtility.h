#ifndef __GUTILITY__
#define __GUTILITY__

#include "includes.h"

extern NTSTATUS MmUnmapViewOfSection(IN PEPROCESS Process, IN PVOID BaseAddress);
extern PVOID *PsGetProcessSectionBaseAddress(IN PEPROCESS Process);
extern CHAR *PsGetProcessImageFileName(IN PEPROCESS Process);

ULONG_PTR GetSDTFunctionByIndex(PSYSTEM_SERVICE_TABLE KiServiceTable, ULONG ServiceId);

BOOLEAN IsValidAddress(PVOID src, ULONG size);
BOOLEAN SafeCopyMemory(PVOID dest, PVOID src, ULONG size);

KIRQL WPOFFx64();
void WPONx64(KIRQL irql);

/*
	LookupProcess

	Finds and returns a pointer to the EPROCESS structure
	by a given process id.
*/
PEPROCESS LookupProcess(ULONG process_id);

/*	
	TerminateProcessByProcessId

	Terminates a process by a given process id.

	Note:
		It is able to terminate protected processes.

	Returns the status of the operation.
	*/
NTSTATUS TerminateProcessByProcessId(ULONG process_id);

/*
	GetProcessNameByProcessId

	Returns the process name by a given process id.
*/
CHAR *GetProcessNameByProcessId(ULONG process_id);

/*
	GetKeServiceDescriptorTable64

	Finds the KeServiceDescriptorTable64 by signature 4C 0D 15 since it's
	not anymore exported by the kernel in x64.

	Note:
		start = nt!KiSystemCall64

	Returns the address to the KeServiceDescriptorTable64
*/
ULONG_PTR GetKeServiceDescriptorTable64();

/*
	GetKeServiceDescriptorTableShadow64

	Finds the KeServiceDescriptorTableShadow64 by signature 4C 0D 1D

	Note:
		start = nt!KiSystemCall64

	Returns the address to the KeServiceDescriptorTableShadow64
*/
ULONG_PTR GetKeServiceDescriptorTableShadow64();

VOID UnlinkProcess(ULONG process_id);
VOID ProtectProcess(ULONG process_id);

#endif