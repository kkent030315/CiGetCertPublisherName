#include "ci.h"

NTSTATUS FakeDriverEntry()
{
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CiGetCertPublisherName(
	_In_ Asn1BlobPtr* Blob,
	_In_ PVOID(*AllocCallback)(ULONG size),
	_Out_ UNICODE_STRING* PublisherName)
{
	UNREFERENCED_PARAMETER(Blob);
	UNREFERENCED_PARAMETER(AllocCallback);
	UNREFERENCED_PARAMETER(PublisherName);

	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS CiValidateFileObject(
    PFILE_OBJECT fileObject,
    int a2,
    int a3,
    PolicyInfo* policyInfoForSigner,
    PolicyInfo* policyInfoForTimestampingAuthority,
    LARGE_INTEGER* signingTime,
    BYTE* digestBuffer,
    int* digestSize,
    int* digestIdentifier)
{
	UNREFERENCED_PARAMETER(fileObject);
	UNREFERENCED_PARAMETER(a2);
	UNREFERENCED_PARAMETER(a3);
	UNREFERENCED_PARAMETER(policyInfoForSigner);
	UNREFERENCED_PARAMETER(policyInfoForTimestampingAuthority);
	UNREFERENCED_PARAMETER(signingTime);
	UNREFERENCED_PARAMETER(digestBuffer);
	UNREFERENCED_PARAMETER(digestSize);
	UNREFERENCED_PARAMETER(digestIdentifier);

	return STATUS_NOT_IMPLEMENTED;
}
