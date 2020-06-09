#include "mem.h"
#include <TlHelp32.h>

DWORD GetProcId(const WCHAR* procName)
{
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32FirstW(hSnap, &procEntry))
		{
			do
			{
				if (!_wcsicmp(procEntry.szExeFile, procName))
				{
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32NextW(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}

CHAR* GetModuleBaseAddress(const WCHAR* modName, DWORD procId)
{
	char* modBaseAddr{ nullptr };
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32W modEntry{};
		modEntry.dwSize = sizeof(modEntry);
		if (Module32FirstW(hSnap, &modEntry))
		{
			do
			{
				std::wcout << "Module: " << modEntry.szModule << "\n\tEXE Path: " << modEntry.szExePath << '\n';
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = reinterpret_cast<char*>(modEntry.modBaseAddr);
					break;
				}
			}
			while (Module32NextW(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

PEB GetPEBExternal(HANDLE hProc)
{
	PROCESS_BASIC_INFORMATION pbi;
	PEB peb = { 0 };

	tNtQueryInformationProcess NtQueryInformationProcess =
		(tNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

	NTSTATUS status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
	if (NT_SUCCESS(status))
	{
		ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr);
	}

	return peb;
}

PPEB GetPEBInternal()
{
#ifdef _WIN64
	PPEB peb = reinterpret_cast<PEB*>(__readgsqword(0x60));

#else
	PPEB peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

	return peb;
}

LDR_DATA_TABLE_ENTRY* GetLDREntryInternal(const WCHAR* modName)
{
	LDR_DATA_TABLE_ENTRY* modEntry = nullptr;

	PEB* peb = GetPEBInternal();

	LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

	LIST_ENTRY curr = head;

	// Iterate through the memory order list of loaded modules 
	for (auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink)
	{
		LDR_DATA_TABLE_ENTRY* mod = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (mod->BaseDllName.Buffer)
		{
			if (_wcsicmp(modName, mod->BaseDllName.Buffer) == 0)
			{
				modEntry = mod;
				break;
			}
		}
	}
	return modEntry;
}

CHAR* GetModuleBaseAddressInternalPEB(const WCHAR* modName)
{
	LDR_DATA_TABLE_ENTRY* modEntry = GetLDREntryInternal(modName);

	return static_cast<char*>(modEntry->DllBase);
}