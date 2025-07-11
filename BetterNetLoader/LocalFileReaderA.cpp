#include "LocalFileReaderA.h"
#include <stdio.h>

BOOL ReadLocalFileA(LPCSTR filePath, PBYTE* pBuffer, PDWORD pSize) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Unable to open local file: %s\n", filePath);
        return FALSE;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[-] GetFileSize failed for: %s\n", filePath);
        CloseHandle(hFile);
        return FALSE;
    }
    PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
    if (!buffer) {
        printf("[-] HeapAlloc failed for local file buffer.\n");
        CloseHandle(hFile);
        return FALSE;
    }
    DWORD bytesRead = 0;
    BOOL readResult = ReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    if (!readResult || bytesRead != fileSize) {
        printf("[-] ReadFile failed for: %s\n", filePath);
        HeapFree(GetProcessHeap(), 0, buffer);
        return FALSE;
    }
    *pBuffer = buffer;
    *pSize = fileSize;
    return TRUE;
}
