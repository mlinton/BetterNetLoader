#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

// Helper: Constructs an absolute path if lpFileName does not contain any path separator.
static void BuildFullPath(LPCTSTR lpFileName, LPTSTR fullPath, size_t fullPathSize)
{
    // Check if lpFileName contains '\' or '/' or ':' to determine if it is a full path.
    if (_tcschr(lpFileName, _T('\\')) || _tcschr(lpFileName, _T('/')) || _tcschr(lpFileName, _T(':')))
    {
        _tcsncpy_s(fullPath, fullPathSize, lpFileName, _TRUNCATE);
    }
    else
    {
        // If a singular name, use the system directory.
        TCHAR sysDir[MAX_PATH] = { 0 };
        if (GetSystemDirectory(sysDir, MAX_PATH))
            _stprintf_s(fullPath, fullPathSize, _T("%s\\%s"), sysDir, lpFileName);
        else
            _tcsncpy_s(fullPath, fullPathSize, lpFileName, _TRUNCATE);
    }
    // Debug print to verify the full path.
    _tprintf(_T("BuildFullPath: %s\n"), fullPath);
}

// A simple manual PE loader that mimics LoadLibraryEx.
// It reads the DLL file from disk, maps it into memory,
// copies headers and sections, applies base relocations, resolves imports,
// and finally calls DllMain with DLL_PROCESS_ATTACH.
// dwFlags may include LOAD_LIBRARY_AS_DATAFILE or DONT_RESOLVE_DLL_REFERENCES.
HMODULE MyLoadLibraryExWrapped(LPCTSTR lpFileName, HANDLE hFileIgnored, DWORD dwFlags)
{
    TCHAR fullPath[MAX_PATH] = { 0 };
    BuildFullPath(lpFileName, fullPath, MAX_PATH);

    // Open the file.
    HANDLE hFile = CreateFile(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        _tprintf(_T("MyLoadLibraryExWrapped: CreateFile failed for %s\n"), fullPath);
        return NULL;
    }

    // Create a file mapping for reading.
    HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hFileMapping)
    {
        CloseHandle(hFile);
        _tprintf(_T("MyLoadLibraryExWrapped: CreateFileMapping failed for %s\n"), fullPath);
        return NULL;
    }

    LPVOID pFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pFileBase)
    {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        _tprintf(_T("MyLoadLibraryExWrapped: MapViewOfFile failed for %s\n"), fullPath);
        return NULL;
    }

    // Validate DOS header.
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pFileBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        UnmapViewOfFile(pFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        _tprintf(_T("MyLoadLibraryExWrapped: Invalid DOS signature in %s\n"), fullPath);
        return NULL;
    }

    // Get NT headers.
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pFileBase + dosHeader->e_lfanew);
    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        UnmapViewOfFile(pFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        _tprintf(_T("MyLoadLibraryExWrapped: Invalid NT signature in %s\n"), fullPath);
        return NULL;
    }

    // Reserve memory for the image.
    SIZE_T imageSize = pNTHeader->OptionalHeader.SizeOfImage;
    LPVOID baseDll = VirtualAlloc((LPVOID)pNTHeader->OptionalHeader.ImageBase, imageSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!baseDll)
        baseDll = VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!baseDll)
    {
        UnmapViewOfFile(pFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        _tprintf(_T("MyLoadLibraryExWrapped: VirtualAlloc failed for %s\n"), fullPath);
        return NULL;
    }

    // Copy headers.
    memcpy(baseDll, pFileBase, pNTHeader->OptionalHeader.SizeOfHeaders);

    // Copy each section.
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNTHeader);
    for (UINT i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
    {
        LPVOID dest = (LPBYTE)baseDll + pSection[i].VirtualAddress;
        LPVOID src = (LPBYTE)pFileBase + pSection[i].PointerToRawData;
        memcpy(dest, src, pSection[i].SizeOfRawData);
    }

    // Clean up file mapping.
    UnmapViewOfFile(pFileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    // If not loaded as data file, perform base relocations.
    if (!(dwFlags & LOAD_LIBRARY_AS_DATAFILE) &&
        (DWORD_PTR)baseDll != pNTHeader->OptionalHeader.ImageBase)
    {
        PIMAGE_DATA_DIRECTORY relocDir = &pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size)
        {
            PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)baseDll + relocDir->VirtualAddress);
            DWORD_PTR delta = (DWORD_PTR)baseDll - pNTHeader->OptionalHeader.ImageBase;
            while (pReloc->VirtualAddress)
            {
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD pRelocData = (PWORD)((LPBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < count; i++)
                {
                    WORD typeOffset = pRelocData[i];
                    WORD type = typeOffset >> 12;
                    WORD offset = typeOffset & 0x0FFF;
                    if (type == IMAGE_REL_BASED_HIGHLOW)
                    {
                        PDWORD pPatch = (PDWORD)((LPBYTE)baseDll + pReloc->VirtualAddress + offset);
                        *pPatch += (DWORD)delta;
                    }
#ifdef _WIN64
                    else if (type == IMAGE_REL_BASED_DIR64)
                    {
                        PULONGLONG pPatch = (PULONGLONG)((LPBYTE)baseDll + pReloc->VirtualAddress + offset);
                        *pPatch += delta;
                    }
#endif
                }
                pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pReloc + pReloc->SizeOfBlock);
            }
        }
    }

    // Process imports (unless loading as data file or if flag to not resolve imports is set).
    if (!(dwFlags & (LOAD_LIBRARY_AS_DATAFILE | DONT_RESOLVE_DLL_REFERENCES)))
    {
        PIMAGE_DATA_DIRECTORY importDir = &pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->Size)
        {
            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)baseDll + importDir->VirtualAddress);
            while (pImportDesc->Name)
            {
                LPCTSTR importName = (LPCTSTR)((LPBYTE)baseDll + pImportDesc->Name);
                // Load dependency using standard LoadLibrary (or recursively call MyLoadLibraryExWrapped if desired).
                HMODULE hImport = LoadLibrary(importName);
                if (!hImport)
                {
                    VirtualFree(baseDll, 0, MEM_RELEASE);
                    _tprintf(_T("MyLoadLibraryExWrapped: Failed to load dependency %s\n"), importName);
                    return NULL;
                }

                PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((LPBYTE)baseDll + pImportDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)baseDll + pImportDesc->FirstThunk);
                while (pOrigThunk->u1.AddressOfData)
                {
                    FARPROC proc = NULL;
                    if (pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    {
                        WORD ordinal = IMAGE_ORDINAL(pOrigThunk->u1.Ordinal);
                        proc = GetProcAddress(hImport, (LPCSTR)ordinal);
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)baseDll + pOrigThunk->u1.AddressOfData);
                        proc = GetProcAddress(hImport, (LPCSTR)pImport->Name);
                    }
                    if (!proc)
                    {
                        VirtualFree(baseDll, 0, MEM_RELEASE);
                        _tprintf(_T("MyLoadLibraryExWrapped: Failed to resolve import in %s\n"), importName);
                        return NULL;
                    }
                    pThunk->u1.Function = (ULONG_PTR)proc;
                    pOrigThunk++;
                    pThunk++;
                }
                pImportDesc++;
            }
        }
    }

    // Call the DLL's entry point (DllMain) for DLL_PROCESS_ATTACH.
    if (!(dwFlags & LOAD_LIBRARY_AS_DATAFILE))
    {
        if (pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
        {
            typedef BOOL(WINAPI* DllMainProc)(HINSTANCE, DWORD, LPVOID);
            DllMainProc pDllMain = (DllMainProc)((LPBYTE)baseDll + pNTHeader->OptionalHeader.AddressOfEntryPoint);
            if (pDllMain)
                pDllMain((HINSTANCE)baseDll, DLL_PROCESS_ATTACH, NULL);
        }
    }

    // Return the base address as the module handle.
    _tprintf(_T("MyLoadLibraryExWrapped: Successfully loaded %s at 0x%p\n"), fullPath, baseDll);
    return (HMODULE)baseDll;
}
