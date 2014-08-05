#include "GUtility.h"
#include "GDriver.h"
#include "GFunctions.h"

NTSTATUS UserRequest_TerminateProcess(PIRP Irp, ULONG *written)
{
	PKILLPROCESS kp = (PKILLPROCESS)Irp->AssociatedIrp.SystemBuffer;
	ULONG i = 0;

	for (i = 0; i < kp->num; i++) {
		if (LookupProcess(kp->pid[i])) {
			CHAR *name = GetProcessNameByProcessId(kp->pid[i]);
			name = name ? name : "UNKNOWN";

			DbgPrint("GDriver: Request to terminate process %s [%04d]", name, kp->pid[i]);

			NTSTATUS ret = TerminateProcessByProcessId(kp->pid[i]);
			if (NT_SUCCESS(ret)) {
				DbgPrint("GDriver: %s [%04d] was successfully terminated.", name, kp->pid[i]);
				kp->status[i] = 0;
			}
			else {
				DbgPrint("GDriver: %s [%04d] could not be terminated.", name, kp->pid[i]);
				kp->status[i] = 1;
			}
		}
		else {
			DbgPrint("GDriver: Requested to terminate process with invalid process id [%04d].", kp->pid[i]);
			kp->status[i] = 2;
		}
	}

	*written = sizeof(KILLPROCESS);

	return STATUS_SUCCESS;
}

NTSTATUS UserRequest_HideProcess(PIRP Irp, ULONG *written)
{
	PHIDEPROCESS hp = (PHIDEPROCESS)Irp->AssociatedIrp.SystemBuffer;
	ULONG i = 0;

	for (i = 0; i < hp->num; i++) {
		if (LookupProcess(hp->pid[i])) {

			CHAR *name = GetProcessNameByProcessId(hp->pid[i]);
			name = name ? name : "UNKNOWN";
			
			DbgPrint("GDriver: Request to hide process %s [%04d]", name, hp->pid[i]);
			
			UnlinkProcess(hp->pid[i]);
		}
		else 
			DbgPrint("GDriver: Requested to hide process with invalid process id [%04d].", hp->pid[i]);
	}

	*written = 0;

	return STATUS_SUCCESS;
}

NTSTATUS UserRequest_ProtectProcess(PIRP Irp, ULONG *written)
{
	PPROTECTPROCESS pp = (PPROTECTPROCESS)Irp->AssociatedIrp.SystemBuffer;
	ULONG i = 0;

	for (i = 0; i < pp->num; i++) {
		if (LookupProcess(pp->pid[i])) {

			CHAR *name = GetProcessNameByProcessId(pp->pid[i]);
			name = name ? name : "UNKNOWN";

			DbgPrint("GDriver: Request to protect process %s [%04d]", name, pp->pid[i]);

			ProtectProcess(pp->pid[i]);
		}
		else
			DbgPrint("GDriver: Requested to protect process with invalid process id [%04d].", pp->pid[i]);
	}

	*written = 0;

	return STATUS_SUCCESS;
}

NTSTATUS UserRequest_GetOpenFileHandleName(PIRP Irp, ULONG *written)
{
	//KIRQL irql = WPOFFx64(); //Raise IRQL to DISPATCH_LEVEL (DPC)

	FILE_OBJECT *file = NULL;
	PIO_STACK_LOCATION pIoStackLocation = NULL;
	FILE_INFO *inout = NULL;
	DEVICE_CONTROL_DATA *dcd = NULL;
	
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	*written = 0;
	
	if (pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(DEVICE_CONTROL_DATA))
		return STATUS_UNSUCCESSFUL;

	dcd = (DEVICE_CONTROL_DATA*)Irp->AssociatedIrp.SystemBuffer;
	if (!IsValidAddress(dcd, sizeof(DEVICE_CONTROL_DATA)))
		return STATUS_UNSUCCESSFUL;

	if (dcd->type != 28)
		return STATUS_UNSUCCESSFUL;

	file = dcd->address;
	inout = (FILE_INFO*)Irp->AssociatedIrp.SystemBuffer;

	if ((ULONG_PTR)file < 0xFFFFFF0000000000)
		return STATUS_UNSUCCESSFUL;

	if (!IsValidAddress(file, sizeof(FILE_OBJECT)) ||
		!IsValidAddress(file->FileName.Buffer, file->FileName.MaximumLength * 2) ||
		!IsValidAddress(file->DeviceObject, sizeof(DEVICE_OBJECT)) || 
		!MmIsNonPagedSystemAddressValid(file))
		return STATUS_UNSUCCESSFUL;


	if (file->DeviceObject->Type != IO_TYPE_DEVICE)
		return STATUS_UNSUCCESSFUL;

	if (file->FileName.Length == 0 || file->FileName.Length >= 260)
		return STATUS_UNSUCCESSFUL;

	if (pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(FILE_INFO))
		return STATUS_UNSUCCESSFUL;

	if (!SafeCopyMemory(inout->filename, file->FileName.Buffer, file->FileName.Length * 2))
		return STATUS_UNSUCCESSFUL;

	inout->filename[file->FileName.Length] = 0;
	
	*written = sizeof(FILE_INFO);

	//WPONx64(irql);

	return STATUS_SUCCESS;
}