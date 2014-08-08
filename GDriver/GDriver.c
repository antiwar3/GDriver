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


VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = STATUS_SUCCESS;

	if (PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessCreationNotify, TRUE) == STATUS_SUCCESS)
		DbgPrint("GDriver: Custom CreateProcessNotify routine was removed.");
	else
		DbgPrint("GDriver: Unable to remove custom CreateProcessNotify routine.");

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

	if (NT_SUCCESS(IoDeleteSymbolicLink(&name_dos)))
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

	if (PsSetCreateProcessNotifyRoutineEx(ProcessCreationNotify, FALSE) == STATUS_SUCCESS)
		DbgPrint("GDriver: CreateProcessNotify routine was set.");
	else
		DbgPrint("GDriver: Unable to set CreateProcessNotify routine.");

	return STATUS_SUCCESS;
}