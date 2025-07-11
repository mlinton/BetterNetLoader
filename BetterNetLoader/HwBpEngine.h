#include <Windows.h>

bool SetUniqueHardwareBreakpoint(unsigned int slot, void* targetAddr);

LONG HandleUniqueHwbpException(PEXCEPTION_POINTERS exPtrs);