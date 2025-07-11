#ifndef LOCALFILEREADER_H
#define LOCALFILEREADER_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

	// Reads a local file specified by filePath into memory.
	// On success, *pBuffer receives the allocated buffer containing the file data,
	// and *pSize receives the size of the file in bytes.
	// Returns TRUE on success, or FALSE on error.
	BOOL ReadLocalFileA(LPCSTR filePath, PBYTE* pBuffer, PDWORD pSize);

#ifdef __cplusplus
}
#endif

#endif // LOCALFILEREADER_H
