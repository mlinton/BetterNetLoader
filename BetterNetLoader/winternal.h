#pragma once
#include <winternl.h>

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName);
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName);
