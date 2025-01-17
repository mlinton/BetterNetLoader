#pragma once
#include <Windows.h>

HRESULT DotnetExecute(
	_In_  PBYTE  AssemblyBytes,
	_In_  ULONG  AssemblySize,
	_In_  PWSTR  AppDomainName,
	_In_  PWSTR  Arguments,
	_Out_ LPSTR* OutputBuffer,
	_Out_ PULONG OutputLength
);

BOOL ReadFileFromURLA(
    IN LPCSTR url,
    OUT PBYTE* ppFileBuffer,
    OUT PDWORD pdwFileSize
);