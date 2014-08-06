#ifndef __GFUNCTIONS__
#define __GFUNCTIONS__

#include "includes.h"

/*
	UserRequest_TerminateProcess

	Teminates a number of processes by usermode app request.
	Return status values are returned to the requestor.

	Return status values:
		SUCCESSFUL	=	0
		FAIL		=	1
		INVALID		=	2
*/
NTSTATUS UserRequest_TerminateProcess(PIRP Irp, ULONG *written);

NTSTATUS UserRequest_HideProcess(PIRP Irp, ULONG *written);

NTSTATUS UserRequest_ProtectProcess(PIRP Irp, ULONG *written);

NTSTATUS UserRequest_GetOpenFileHandleName(PIRP Irp, ULONG *written);

VOID ProcessCreationNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);

#endif