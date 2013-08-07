#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "Structures.h"

/*-----------------------------------------------------------------------------
	IMAGE_FIRST_SECTION32 - Redefined here to remove dependency on NT SDK
-----------------------------------------------------------------------------*/
#define IMAGE_FIRST_SECTION32( ntheader ) ((PIMAGE_SECTION_HEADER)         \
    ((UINT_PTR)ntheader +                                                  \
     FIELD_OFFSET( IMAGE_NT_HEADERS32, OptionalHeader ) +                  \
     ((PIMAGE_NT_HEADERS32)(ntheader))->FileHeader.SizeOfOptionalHeader    \
    ))

/*-----------------------------------------------------------------------------
	RvaToOffset - Convert a relative virtual address to a file offset
-----------------------------------------------------------------------------*/
DWORD RvaToOffset(PVOID pModuleBase, DWORD dwRva)
{
	PIMAGE_DOS_HEADER		pDOSHeader			= NULL;
	PIMAGE_NT_HEADERS		pNTHeader			= NULL;		
	PIMAGE_SECTION_HEADER	pSectionHeader		= NULL;
	DWORD					dwSectionNum		= NULL;	
	DWORD					dwOldRva			= dwRva;

	try
	{				
		pDOSHeader = (PIMAGE_DOS_HEADER)pModuleBase;  
		if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
			throw;
		pNTHeader = (PIMAGE_NT_HEADERS)((LONG)pDOSHeader + pDOSHeader->e_lfanew);
		if (pNTHeader->Signature != LOWORD(IMAGE_NT_SIGNATURE))
			throw;		
		pSectionHeader = IMAGE_FIRST_SECTION32(pNTHeader);
		dwSectionNum = pNTHeader->FileHeader.NumberOfSections;

		for (DWORD i = 0; i < dwSectionNum; ++i)
		{			
			// Check if rva is within this section
			if (pSectionHeader->VirtualAddress <= dwRva && pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress > dwRva)
			{				
				// Calculate offset relative to RVA of section
				dwRva -= pSectionHeader->VirtualAddress;
				// Now add the RVA of the section
				dwRva += pSectionHeader->PointerToRawData;
				// And return				
				return dwRva;
			}

			pSectionHeader++;
		}
	}
	catch(...) {}	

	// Invalid offset => -1
	return -1;
}

typedef INT (*LPFN_INIT) (SOCKET);
//typedef BOOL(*LPFN_DLLMAIN) (HINSTANCE , DWORD , LPVOID  );

int main(int argc, char** argv)
{
	DWORD	dwFileSizeLow				= NULL;
	DWORD	dwFileSizeHigh				= NULL;
	DWORD	dwOffset					= NULL;
	DWORD	dwDummy						= -1;
	PVOID	pAddressOfReflectiveLoader	= NULL;
	PVOID	pAddressOfInit				= NULL;
	HMODULE	hDll						= NULL;
	FARPROC	pInit						= NULL;
	HMODULE hNewDll						= NULL;

	/*
	hDll = LoadLibraryA("ReflectiveDLL.dll");
	pInit = GetProcAddress(hDll, "_ReflectiveLoader@4");

	printf("Base: 0x%08X\n", hDll);

	__asm
	{
		push dword ptr[hDll]
		call dword ptr[pInit]
	}
	*/
	
	/* STEP 1: Dump in buffer */
	printf("Loading file: %s\n", "dnsTunnelDll.dll");

	HANDLE hFile = CreateFileA(
		"dnsTunnelDll.dll", 
		GENERIC_READ, 
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL);

	dwFileSizeLow = GetFileSize(hFile, &dwFileSizeHigh);
	printf("> File Size: %d bytes\n", dwFileSizeLow);

	PBYTE pDllBuffer = new BYTE[dwFileSizeLow];

	while(dwDummy)
	{
		ReadFile(hFile, pDllBuffer + dwOffset, 512, &dwDummy, NULL);
		dwOffset += dwDummy;
		//printf("> Read %d bytes - Offset = %d\n", dwDummy, dwOffset);
	}

	CloseHandle(hFile);

	VirtualProtect(pDllBuffer, dwFileSizeLow, PAGE_EXECUTE_READWRITE, &dwDummy);

	/* STEP 2: Call Reflective Loader to rewrite dll */
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pDllBuffer;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_EXPORT_DIRECTORY	pExports;
	PDWORD pENT;
	PDWORD pEAT;

	if (pDOSHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		pNTHeader	= (PIMAGE_NT_HEADERS)((DWORD)pDllBuffer + pDOSHeader->e_lfanew);
		pExports	= (PIMAGE_EXPORT_DIRECTORY)(pDllBuffer + RvaToOffset(pDllBuffer, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
		
		pENT		= (PDWORD)(pDllBuffer + RvaToOffset(pDllBuffer, pExports->AddressOfNames));
		pEAT		= (PDWORD)(pDllBuffer + RvaToOffset(pDllBuffer, pExports->AddressOfFunctions));		

		for (DWORD i = 0; i < pExports->NumberOfNames; ++i)
		{
			LPSTR szFunctionName = (LPSTR)(pDllBuffer + RvaToOffset(pDllBuffer, pENT[i]));			

			if (!strcmp(szFunctionName, "_ReflectiveLoader@0")){		//The reflective loader symbol name	
				pAddressOfReflectiveLoader = (PVOID)(pDllBuffer + RvaToOffset(pDllBuffer, pEAT[i]));	
				printf("Found the ReflectiveLoader address inside the DLL\n");
			}else{
				printf("Found symbol in DLL - %s\n", szFunctionName);
			}
		}
	}

	__asm
	{
		//push dword ptr[pDllBuffer]
		call dword ptr[pAddressOfReflectiveLoader]
		mov dword ptr[hNewDll], eax
	}	

	pDOSHeader = (PIMAGE_DOS_HEADER)hNewDll;

	if (pDOSHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		pNTHeader	= (PIMAGE_NT_HEADERS)((DWORD)pDllBuffer + pDOSHeader->e_lfanew);
		pExports	= (PIMAGE_EXPORT_DIRECTORY)(pDllBuffer + RvaToOffset(pDllBuffer, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
		
		pENT		= (PDWORD)(pDllBuffer + RvaToOffset(pDllBuffer, pExports->AddressOfNames));
		pEAT		= (PDWORD)(pDllBuffer + RvaToOffset(pDllBuffer, pExports->AddressOfFunctions));

		for (DWORD i = 0; i < pExports->NumberOfNames; ++i)
		{
			LPSTR szFunctionName = (LPSTR)(pDllBuffer + RvaToOffset(pDllBuffer, pENT[i]));	

			if (!strcmp(szFunctionName, "Init")){ //The symbol name of the function we want to call
				pAddressOfInit = (PVOID)((DWORD)hNewDll + pEAT[i]);
				printf("Found address of Init function\n");
			}
		}
	}
	
	printf("Loading file: %s\n", "dnsTunnelDll.dll");
	
	LPFN_INIT pInitFunc = (LPFN_INIT)pAddressOfInit;	
	//LPFN_DLLMAIN pDllFunc = (LPFN_DLLMAIN)hNewDll;	
	//pDllFunc(0,0,0);
	pInitFunc(0);

	printf("Done\n");
	
}