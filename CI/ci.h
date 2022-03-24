#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <minwindef.h>

// https://github.com/Ido-Moshe-Github/CiDllDemo/blob/master/CiDemoDriver/ci.h
typedef struct _Asn1BlobPtr
{
    int size;               // size of the ASN.1 blob
    PVOID ptrToData;        // where the ASN.1 blob starts
} Asn1BlobPtr, * pAsn1BlobPtr;

// https://github.com/Ido-Moshe-Github/CiDllDemo/blob/master/CiDemoDriver/ci.h
typedef struct _CertificatePartyName
{
    PVOID pointerToName;
    short nameLen;
    short unknown;
} CertificatePartyName, * pCertificatePartyName;

// https://github.com/Ido-Moshe-Github/CiDllDemo/blob/master/CiDemoDriver/ci.h
typedef struct _CertChainMember
{
    int digestIdetifier;                // e.g. 0x800c for SHA256
    int digestSize;                     // e.g. 0x20 for SHA256
    BYTE digestBuffer[64];              // contains the digest itself, where the digest size is dictated by digestSize

    CertificatePartyName subjectName;   // pointer to the subject name
    CertificatePartyName issuerName;    // pointer to the issuer name

    Asn1BlobPtr certificate;            // ptr to actual cert in ASN.1 - including the public key
} CertChainMember, * pCertChainMember;

// https://github.com/Ido-Moshe-Github/CiDllDemo/blob/master/CiDemoDriver/ci.h
typedef struct _CertChainInfoHeader
{
    // The size of the dynamically allocated buffer
    int bufferSize;

    // points to the start of a series of Asn1Blobs which contain the public keys of the certificates in the chain
    pAsn1BlobPtr ptrToPublicKeys;
    int numberOfPublicKeys;

    // points to the start of a series of Asn1Blobs which contain the EKUs
    pAsn1BlobPtr ptrToEkus;
    int numberOfEkus;

    // points to the start of a series of CertChainMembers
    pCertChainMember ptrToCertChainMembers;
    int numberOfCertChainMembers;

    int unknown;

    // ASN.1 blob of authenticated attributes - spcSpOpusInfo, contentType, etc.
    Asn1BlobPtr variousAuthenticodeAttributes;
} CertChainInfoHeader, * pCertChainInfoHeader;

// https://github.com/Ido-Moshe-Github/CiDllDemo/blob/master/CiDemoDriver/ci.h
typedef struct _PolicyInfo
{
    int structSize;
    NTSTATUS verificationStatus;
    int flags;
    pCertChainInfoHeader certChainInfo; // if not null - contains info about certificate chain
    FILETIME revocationTime;            // when was the certificate revoked (if applicable)
    FILETIME notBeforeTime;             // the certificate is not valid before this time
    FILETIME notAfterTime;              // the certificate is not valid before this time
} PolicyInfo, * pPolicyInfo;

// https://github.com/Ido-Moshe-Github/CiDllDemo/blob/master/CiDemoDriver/ci.h
EXTERN_C __declspec(dllexport) NTSTATUS CiValidateFileObject(
    PFILE_OBJECT fileObject,
    int a2,
    int a3,
    PolicyInfo* policyInfoForSigner,
    PolicyInfo* policyInfoForTimestampingAuthority,
    LARGE_INTEGER* signingTime,
    BYTE* digestBuffer,
    int* digestSize,
    int* digestIdentifier);

EXTERN_C __declspec(dllexport) NTSTATUS CiGetCertPublisherName(
	_In_ Asn1BlobPtr* Blob ,
	_In_ PVOID(*AllocCallback)(ULONG size),
	_Out_ UNICODE_STRING* PublisherName);
