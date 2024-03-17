#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

#include "binaryarray.h"

using namespace std;

std::vector<DWORD> PidList;
DWORD FindProcessId(const char* ProcessName) {
	PidList.clear();
	PROCESSENTRY32 Processes;
	Processes.dwSize = sizeof(Processes);
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Process32First(Snapshot, &Processes);
	do {
		if (!strcmp(ProcessName, Processes.szExeFile)) {
			PidList.push_back(Processes.th32ProcessID);
		}
	} while (Process32Next(Snapshot, &Processes));
	CloseHandle(Snapshot);
	return PidList[PidList.size() - 1];
}

//typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
//typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

typedef struct
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	HMODULE(WINAPI* loadLibraryA)(PCSTR);
	FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
} LoaderData;

DWORD __stdcall LibraryLoader(LPVOID Memory) {

	LoaderData* LoaderParams = (LoaderData*)Memory;
	PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;
	DWORD64 delta = (DWORD64)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(DWORD);// WARNING EDDITED FROM WORD
			PWORD list = (PWORD)(pIBR + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

		HMODULE hModule = LoaderParams->loadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				DWORD64 Function = (DWORD64)LoaderParams->getProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD64 Function = (DWORD64)LoaderParams->getProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

		return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}

DWORD __stdcall stub() { return 0; }

int main(int argc, char* argv[])
{
	const char* targetProc = "cs2.exe";
	DWORD ProcessId = FindProcessId(targetProc);
	std::cout << "Got Process id : " << ProcessId << std::endl;

	LoaderData LoaderParams;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)binary;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(binary + ((PIMAGE_DOS_HEADER)binary)->e_lfanew);

	// Opening target process.
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (hProcess == NULL) {
		std::cout << "cant open process Run As Admin" << std::endl; return -1;
	}
	std::cout << "opend Process: " << hProcess << std::endl;

	// Allocating memory for the DLL
	PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// Copy the headers to target process
	WriteProcessMemory(hProcess, ExecutableImage, binary,
		pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// Target Dll's Section Header
	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
	// Copying sections of the dll to the target process
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
			binary + pSectHeader[i].PointerToRawData, pSectHeader[i].SizeOfRawData, NULL);
	}

	// Allocating memory for the loader code.
	PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

	LoaderParams.ImageBase = ExecutableImage;
	LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);

	LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	LoaderParams.loadLibraryA = LoadLibraryA;
	LoaderParams.getProcAddress = GetProcAddress;

	// Write the loader information to target process
	WriteProcessMemory(hProcess, LoaderMemory, &LoaderParams, sizeof(LoaderData),
		NULL);
	// Write the loader code to target process
	WriteProcessMemory(hProcess, (PVOID)((LoaderData*)LoaderMemory + 1), LibraryLoader,
		(DWORD64)stub - (DWORD64)LibraryLoader, NULL);
	// Create a remote thread to execute the loader code
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((LoaderData*)LoaderMemory + 1),
		LoaderMemory, 0, NULL);


	CloseHandle(hThread);//
	CloseHandle(hProcess);//
	VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);

	return 0;
}