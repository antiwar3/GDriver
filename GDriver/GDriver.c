#include <Ntifs.h>
#include <ntddk.h>
#include "GDriver.h"
#include "GUtility.h"
#include "GFunctions.h"
#include "includes.h"

_NtQuerySystemTime pNtQuerySystemTime = NULL;
_NtQuerySystemInformation pNtQuerySystemInformation = NULL;
_NtOpenProcess pNtOpenProcess = NULL;
_NtTerminateProcess pNtTerminateProcess = NULL;
_NtDuplicateObject pNtDuplicateObject = NULL;
_NtQueryObject pNtQueryObject = NULL;
_NtClose pNtClose = NULL;

PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable = NULL;
PSYSTEM_SERVICE_TABLE g_pSSDT = NULL;
PSYSTEM_SERVICE_TABLE g_pSSDTS = NULL;

VOID CreateProcessNotifyEx(__inout PEPROCESS Process, __in HANDLE ProcessId, __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo);

VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;

	PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateProcessNotifyEx, TRUE);

	UNICODE_STRING name_dos;
	RtlInitUnicodeString(&name_dos, dosDeviceName);

	status = IoDeleteSymbolicLink(&name_dos);
	if (status != STATUS_SUCCESS) 
		DbgPrint("GDriver: IoDeleteSymbolicLink has failed.");

	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("GDriver: unloaded.");
}

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("GDriver: DispatchCreate");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("GDriver: DispatchClose");

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp)
{
	//DbgPrint("GDriver: DispatchDeviceControl\n");

	ULONG written = 0;
	NTSTATUS status = STATUS_SUCCESS;

	try {
		PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);

		if (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_GDRIVER_TERMINATEPROCESS) {
			status = UserRequest_TerminateProcess(Irp, &written);
		}
		else if (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_GDRIVER_OPENFILES) {
			status = UserRequest_GetOpenFileHandleName(Irp, &written);
		}
		else if (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_GDRIVER_HIDEPROCESS) {
			status = UserRequest_HideProcess(Irp, &written);
		}
		else if (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_GDRIVER_PROTECTPROCESS) {
			status = UserRequest_ProtectProcess(Irp, &written);
		}
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("GDriver: EXCEPTION[DispatchDeviceControl]");
		status = STATUS_ACCESS_VIOLATION;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = written;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI hkNtTerminateProcess(HANDLE handle, NTSTATUS exitcode)
{

	return pNtTerminateProcess(handle, exitcode);
}

VOID CreateProcessNotifyEx(__inout PEPROCESS Process, __in HANDLE ProcessId, __in_opt PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	if (CreateInfo) {
		DbgPrint("GDriver: NOTIFY[Process %s (%04d) was created]", GetProcessNameByProcessId((ULONG)ProcessId), ProcessId);
		//CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
	}
	else {
		DbgPrint("GDriver: NOTIFY[Process %s [%04d] was terminated]", GetProcessNameByProcessId((ULONG)ProcessId), ProcessId);
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNICODE_STRING  name_nt, name_dos;
	PDEVICE_OBJECT  pDeviceObject;
	NTSTATUS ntStatus;

	RtlInitUnicodeString(&name_nt, driverName);
	RtlInitUnicodeString(&name_dos, dosDeviceName);

	DbgPrint("GDriver: starting.");

	ntStatus = IoCreateDevice(DriverObject, 0, &name_nt, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (ntStatus != STATUS_SUCCESS) {
		DbgPrint("GDriver: IoCreateDevice has failed.");
		return ntStatus;
	}

	if (IoDeleteSymbolicLink(&name_dos) == STATUS_SUCCESS) 
		DbgPrint("GDriver: Previous or old symbolic link was deleted.");
	
	ntStatus = IoCreateSymbolicLink(&name_dos, &name_nt);
	if (ntStatus != STATUS_SUCCESS) {
		DbgPrint("GDriver: IoCreateSymbolicLink has failed.");
		IoDeleteDevice(DriverObject->DeviceObject);
		return STATUS_UNSUCCESSFUL;
	}

	DriverObject->DriverUnload = UnloadDriver;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

	KeServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)GetKeServiceDescriptorTable64();

	g_pSSDT = (PSYSTEM_SERVICE_TABLE)KeServiceDescriptorTable->ntoskrnl.ServiceTable;
	g_pSSDTS = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTableShadow64();

	DbgPrint("GDriver: SSDT found at %p.", g_pSSDT);
	DbgPrint("GDriver: SSDTS found at %p.", g_pSSDTS);

	pNtQuerySystemTime = (_NtQuerySystemTime)GetSDTFunctionByIndex(g_pSSDT, 0x57);
	pNtQuerySystemInformation = (_NtQuerySystemInformation)GetSDTFunctionByIndex(g_pSSDT, 0x33);
	pNtOpenProcess = (_NtOpenProcess)GetSDTFunctionByIndex(g_pSSDT, 0x23);
	pNtTerminateProcess = (_NtTerminateProcess)GetSDTFunctionByIndex(g_pSSDT, 0x29);
	pNtDuplicateObject = (_NtDuplicateObject)GetSDTFunctionByIndex(g_pSSDT, 0x39);
	pNtQueryObject = (_NtQueryObject)GetSDTFunctionByIndex(g_pSSDT, 0x0D);
	pNtClose = (_NtClose)GetSDTFunctionByIndex(g_pSSDT, 0x0C);

	DbgPrint("GDriver: SSDT[0x0C] -> NtClose: %p", pNtClose);
	DbgPrint("GDriver: SSDT[0x0D] -> NtQueryObject: %p", pNtQueryObject);
	DbgPrint("GDriver: SSDT[0x23] -> NtOpenProcess: %p", pNtOpenProcess);
	DbgPrint("GDriver: SSDT[0x29] -> NtTerminateProcess: %p", pNtTerminateProcess);
	DbgPrint("GDriver: SSDT[0x33] -> NtQuerySystemInformation: %p", pNtQuerySystemInformation);
	DbgPrint("GDriver: SSDT[0x39] -> NtDuplicateObject: %p", pNtDuplicateObject);
	DbgPrint("GDriver: SSDT[0x57] -> NtQuerySystemTime: %p", pNtQuerySystemTime);

	DbgPrint("GDriver: loaded.");

	//KIRQL irql = WPOFFx64();
	//DbgPrint("GDriver: In DISPATCH_LEVEL");
	//WPONx64(irql);

	NTSTATUS lol = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)CreateProcessNotifyEx, FALSE);
	DbgPrint("kk %x", lol);
	//try {
	//	PEPROCESS *ep = LookupProcess(948);

	//	if (ep) {

	//		PLIST_ENTRY cur = (PLIST_ENTRY)((ULONG_PTR)ep + 0x188);
	//		PLIST_ENTRY prev = cur->Blink;
	//		PLIST_ENTRY next = cur->Flink;

	//		prev->Flink = cur->Flink;
	//		next->Blink = cur->Blink;

	//		cur->Flink = cur;
	//		cur->Blink = cur;
	//	}

	//	/*do {
	//		CHAR *name = (char*)ep + 0x2E0;
	//		PLIST_ENTRY list = (PLIST_ENTRY)((ULONG_PTR)ep + 0x188);

	//		name = (char*)ep + 0x2E0;
	//		DbgPrint("%s", name);

	//		ep = (PEPROCESS)(((ULONG_PTR)list->Flink) - 0x188);
	//	} while (ep != PsGetCurrentProcess());*/
	//}
	//except(1)
	//{

	//}

	return STATUS_SUCCESS;
}