#pragma once
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

static void BuildFullPath(LPCTSTR lpFileName, LPTSTR fullPath, size_t fullPathSize);
HMODULE MyLoadLibraryExWrapped(LPCTSTR lpFileName, HANDLE hFileIgnored, DWORD dwFlags); 
