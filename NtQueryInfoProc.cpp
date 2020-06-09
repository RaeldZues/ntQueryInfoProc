#include "mem.h"
#include <iostream>
#include <windows.h>


int wmain()
{
	const WCHAR* data = L"kernel32.dll";
	auto* modBase1 = GetModuleBaseAddress(data, GetCurrentProcessId());
	auto* modBase2 = GetModuleBaseAddressInternalPEB(L"kernel32.dll");

	std::getchar();

	return 0;
}