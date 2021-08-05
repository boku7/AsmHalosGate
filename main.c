/*
Author: Bobby Cooke @0xBoku | https://github.com/boku7 | https://0xBoku.com | https://www.linkedin.com/in/bobby-cooke/
Credits / References: Pavel Yosifovich (@zodiacon),Reenz0h from @SEKTOR7net, @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique)
*/
#include <Windows.h>
#include "bcookesHalosGate.h"
#include <stdio.h>

extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

EXTERN_C PVOID getntdll();

EXTERN_C PVOID getExportTable(
	IN PVOID moduleAddr
);

EXTERN_C PVOID getExAddressTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

EXTERN_C PVOID getExNamePointerTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

EXTERN_C PVOID getExOrdinalTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

EXTERN_C PVOID getApiAddr(
	IN DWORD apiNameStringLen,
	IN LPSTR apiNameString,
	IN PVOID moduleAddr,
	IN PVOID ExExAddressTable,
	IN PVOID ExNamePointerTable,
	IN PVOID ExOrdinalTable
);

EXTERN_C DWORD findSyscallNumber(
	IN PVOID ntdllApiAddr
);

EXTERN_C DWORD halosGate(
	IN PVOID ntdllApiAddr,
	IN WORD index
);

EXTERN_C DWORD compExplorer(
	IN PVOID explorerWString
);

PVOID ntdll = NULL;
PVOID ntdllExportTable = NULL;

PVOID ntdllExAddrTbl = NULL;
PVOID ntdllExNamePtrTbl = NULL;
PVOID ntdllExOrdinalTbl = NULL;

const char ntQrySysInfoStr[] = "NtQuerySystemInformation";
DWORD ntQrySysInfoStrLen = 0;
PVOID ntQrySysInfoAddr = NULL;
DWORD  ntQrySysInfoSyscallNumber = 0;

const char ntAllocVMStr[] = "NtAllocateVirtualMemory";
DWORD ntAllocVMStrLen = 0;
PVOID ntAllocVMAddr = NULL;
DWORD ntAllocVMSyscallNumber = 0;

SYSTEM_PROCESS_INFORMATION* procinfo;

void main() {
	printf("###################################################################\r\n");
	// Use Position Independent Shellcode to resolve the address of NTDLL and its export tables
	ntdll = getntdll();
	printf("[+] %p : NTDLL Base Address\r\n", ntdll);

	ntdllExportTable = getExportTable(ntdll);
	printf("[+] %p : NTDLL Export Table Address\r\n", ntdllExportTable);

	ntdllExAddrTbl = getExAddressTable(ntdllExportTable, ntdll);
	printf("[+] %p : NTDLL Export Address Table Address\r\n", ntdllExAddrTbl);

	ntdllExNamePtrTbl = getExNamePointerTable(ntdllExportTable, ntdll);
	printf("[+] %p : NTDLL Export Name Pointer Table Address\r\n", ntdllExNamePtrTbl);

	ntdllExOrdinalTbl = getExOrdinalTable(ntdllExportTable, ntdll);
	printf("[+] %p : NTDLL Export Ordinal Table Address\r\n", ntdllExOrdinalTbl);
	printf("###################################################################\r\n\r\n");
	// Find the address of NTDLL.NtQuerySystemInformation by looping through NTDLL export tables
	ntQrySysInfoStrLen = sizeof(ntQrySysInfoStr);
	printf("[-] Looping through NTDLL Export tables to discover the address for NTDLL.%s..\r\n", ntQrySysInfoStr);
	ntQrySysInfoAddr = getApiAddr(
		ntQrySysInfoStrLen,
		ntQrySysInfoStr,
		ntdll,
		ntdllExAddrTbl,
		ntdllExNamePtrTbl,
		ntdllExOrdinalTbl
	);
	printf("[+] %p : NTDLL.%s Address\r\n\r\n", ntQrySysInfoAddr, ntQrySysInfoStr);
	printf("[-] Using HellsGate technique to discover syscall for %s..\r\n", ntQrySysInfoStr);
	// HellsGate technique to recover the systemcall number
	ntQrySysInfoSyscallNumber = findSyscallNumber(ntQrySysInfoAddr);
	// HalosGate technique to recover the systemcall number. Used when stub in NTDLL is hooked. This evades/bypasses EDR Userland hooks
	if (ntQrySysInfoSyscallNumber == 0) {
		printf("[!] Failed to discover the syscall number for %s. The API is likely hooked by EDR\r\n", ntQrySysInfoStr);
		printf("[-] Using HalosGate technique to discover syscall for %s..\r\n", ntQrySysInfoStr);
		DWORD index = 0;
		while (ntQrySysInfoSyscallNumber == 0) {
			index++;
			// Check for unhooked Sycall Above the target stub
			ntQrySysInfoSyscallNumber = halosGateUp(ntQrySysInfoAddr, index);
			if (ntQrySysInfoSyscallNumber) {
				ntQrySysInfoSyscallNumber = ntQrySysInfoSyscallNumber - index;
				break;
			}
			// Check for unhooked Sycall Below the target stub
			ntQrySysInfoSyscallNumber = halosGateDown(ntQrySysInfoAddr, index);
			if (ntQrySysInfoSyscallNumber) {
				ntQrySysInfoSyscallNumber = ntQrySysInfoSyscallNumber + index;
				break;
			}
		}
	}
	printf("[+] %x : Syscall number for NTDLL.%s\r\n\r\n", ntQrySysInfoSyscallNumber, ntQrySysInfoStr);

	// Find the address of NTDLL.NtAllocateVirtualMemory by looping through NTDLL export tables
	ntAllocVMStrLen = sizeof(ntAllocVMStr);
	ntAllocVMAddr = getApiAddr(
		ntAllocVMStrLen,
		ntAllocVMStr,
		ntdll,
		ntdllExAddrTbl,
		ntdllExNamePtrTbl,
		ntdllExOrdinalTbl
	);
	printf("[+] %p : NTDLL.%s Address\r\n", ntAllocVMAddr, ntAllocVMStr);
	printf("[-] Using HellsGate technique to discover syscall for %s..\r\n", ntAllocVMStr);
	// HellsGate technique to recover the systemcall number
	ntAllocVMSyscallNumber = findSyscallNumber(ntAllocVMAddr);
	// HalosGate technique to recover the systemcall number. Used when stub in NTDLL is hooked. This evades/bypasses EDR Userland hooks
	if (ntAllocVMSyscallNumber == 0) {
		printf("[!] Failed to discover the syscall number for %s. The API is likely hooked by EDR\r\n", ntAllocVMStr);
		printf("[-] Using HalosGate technique to discover syscall for %s..\r\n", ntAllocVMStr);
		DWORD index = 0;
		while (ntAllocVMSyscallNumber == 0) {
			index++;
			// Check for unhooked Sycall Above the target stub
			ntAllocVMSyscallNumber = halosGateUp(ntAllocVMAddr, index);
			if (ntAllocVMSyscallNumber) {
				ntAllocVMSyscallNumber = ntAllocVMSyscallNumber - index;
				break;
			}
			// Check for unhooked Sycall Below the target stub
			ntAllocVMSyscallNumber = halosGateDown(ntAllocVMAddr, index);
			if (ntAllocVMSyscallNumber) {
				ntAllocVMSyscallNumber = ntAllocVMSyscallNumber + index;
				break;
			}
		}
	}
	printf("[+] %x : Syscall number for NTDLL.%s\r\n\r\n", ntAllocVMSyscallNumber, ntAllocVMStr);

	// Allocate the buffer for the process information returned from NtQuerySystemInformation
	ULONG size = 1 << 18;
	PVOID base_addr = NULL;
	SIZE_T buffSize1 = (SIZE_T)size;
	ULONG required = 0;

	// NtAllocateVirtualMemory
	HellsGate(ntAllocVMSyscallNumber);
	HellDescent((HANDLE)-1, &base_addr, 0, &buffSize1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// NtQuerySystemInformation
	HellsGate(ntQrySysInfoSyscallNumber);

	NTSTATUS status = HellDescent(SystemProcessInformation, base_addr, size, &required);

	if (status == STATUS_BUFFER_TOO_SMALL) {
		size = required + (1 << 14);
		SIZE_T buffSize2 = size;
		// NtAllocateVirtualMemory
		HellsGate(ntAllocVMSyscallNumber);
		HellDescent((HANDLE)-1, &base_addr, 0, &buffSize2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}

	NTSTATUS status2 = HellDescent(SystemProcessInformation, base_addr, size, &required);

	procinfo = (SYSTEM_PROCESS_INFORMATION*)base_addr;
	while (TRUE) {
		BOOL check = compExplorer(procinfo->ImageName.Buffer);
		if (check == 1) {
			printf("%ws | PID: %6u | PPID: %6u\n",
				procinfo->ImageName.Buffer,
				HandleToULong(procinfo->UniqueProcessId),
				HandleToULong(procinfo->InheritedFromUniqueProcessId)
			);
			break;
		}
		procinfo = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)procinfo + procinfo->NextEntryOffset);
	}
	return;
}