#pragma once
#include <Windows.h>
#include <wininet.h>

BOOL ReadFileFromURLA(
    IN LPCSTR url,
    OUT PBYTE* ppFileBuffer,
    OUT PDWORD pdwFileSize
);