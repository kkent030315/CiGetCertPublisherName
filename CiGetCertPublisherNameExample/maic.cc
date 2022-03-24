#include "../CI/ci.h"

#define DPRINTF(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[ci] " format, __VA_ARGS__)

PVOID AllocCallback(ULONG size)
{
	return ExAllocatePool(NonPagedPoolNx, size);
}

VOID ProcessExCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	NTSTATUS status;

	if (ProcessId && CreateInfo)
	{
		PolicyInfo signerPolicyInfo;
		PolicyInfo timestampingAuthorityPolicyInfo;
		LARGE_INTEGER signingTime = {};
		int digestSize = 64;
		int digestIdentifier = 0;
		BYTE digestBuffer[64] = {};
		status = CiValidateFileObject(CreateInfo->FileObject, 0, 0, &signerPolicyInfo, &timestampingAuthorityPolicyInfo, &signingTime, digestBuffer, &digestSize, &digestIdentifier);
		if (NT_SUCCESS(status))
		{
			UNICODE_STRING PublisherName;
			status = CiGetCertPublisherName(&signerPolicyInfo.certChainInfo->ptrToCertChainMembers->certificate, &AllocCallback, &PublisherName);
			if (NT_SUCCESS(status))
			{
				DPRINTF("CiGetCertPublisherName: %wZ\n", &PublisherName);
			}
		}
	}
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PsSetCreateProcessNotifyRoutineEx(ProcessExCallback, TRUE);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;

	DriverObject->DriverUnload = &DriverUnload;

	status = PsSetCreateProcessNotifyRoutineEx(ProcessExCallback, FALSE);
	if (!NT_SUCCESS(status))
		return status;

	return STATUS_SUCCESS;
}