#include <Windows.h>

BOOL HwbpEngineBreakpoint(
    _In_ ULONG Position,
    _In_ PVOID Function
);

BOOL HwbpEngineHandler(
    _Inout_ PEXCEPTION_POINTERS Exceptions
);