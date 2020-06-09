#pragma once
#include "ntapi.h"
#include <windows.h>


// Returns the procid of the process name of interest
// TODO: identify a method to work with finding the right process with duplicate names
DWORD GetProcId(const WCHAR* procName);

// Windows method of obtaining the base address of a module 
CHAR* GetModuleBaseAddress(const WCHAR* modName, DWORD procId);

// Obtain the process environment block of a process passed 
PEB GetPEBExternal(HANDLE hProc);

// Obtain the process environment block using the current process 
PPEB GetPEBInternal();

// Walk the PEB and get the ldr entry table to identify the module name 
LDR_DATA_TABLE_ENTRY* GetLDREntryInternal(const WCHAR* modName);

// wrapper function to get the base address of a module. 
CHAR* GetModuleBaseAddressInternalPEB(const WCHAR* modName);