# Alphabet Soup: Payload Obfuscation & Reconstruction

## Overview
**Alphabet Soup** is a payload obfuscation technique that leverages **Living off the Land (LotL)** principles to evade modern detection engines. 

Instead of storing shellcode in a predictable format (like XOR, Base64, or AES), this technique treats existing system files—such as `.chm`, `.dll`, or `.exe` files—as a **dictionary**. It "harvests" the offsets of specific bytes from these trusted files to reconstruct the payload dynamically in memory at runtime.

## Key Functionality
* **LotL Binary Harvesting:** Reconstructs malicious payloads using bytes sourced from trusted, Microsoft-signed binaries.
* **Environmental Keying:** Supports optional **XOR encoding** tied to the target's **Volume Serial Number**, ensuring the payload is only reconstructible on the specific target machine.
* **Static Evasion:** Converts identifiable shellcode into an array of `unsigned long long` integers. This removes executable entropy and makes the data appear as non-executable program logic or metadata.
* **Polymorphic Output:** The encoder selects byte offsets randomly. Every generation produces a unique array, making static string or byte-sequence signatures impossible.

## ⚠️ Research Scope & Disclaimer
**Alphabet Soup is a Proof of Concept (PoC) for data obfuscation and environmental keying.** It is important to note:
* **Obfuscation, not Injection:** The core of this project is the *Alphabet Soup* reconstruction logic. The provided loaders use standard, well-known injection techniques (e.g., `CreateRemoteThread`, module stomping, dynamic function resolution).
* **Educational Purpose:** This project does not introduce new process injection primitives. It is designed to demonstrate how Living off the Land (LotL) files can be used to bypass static signature detection of shellcode.
* **Modular Design:** The reconstruction logic is designed to be injection-agnostic. It returns a `std::vector<BYTE>` which can be used with any execution technique, including Process Hollowing, APC Injection, or Module Overloading.

---

## PoC Workflow

### 1. Payload Generation
Generate your raw shellcode in C format (e.g., using `msfvenom` or a custom framework).
> `msfvenom -p windows/x64/exec CMD=calc.exe -f c EXITFUNC=thread`

### 2. Encoding the "Soup"
Run the helper script to map your shellcode to a target dictionary file. This PoC utilizes **Windows CHM files** (Compiled HTML Help) for several strategic reasons:
* **Low Suspicion:** CHM files are rarely monitored for read-access by EDRs compared to sensitive system DLLs like `ntdll.dll`.
* **Ubiquity:** Files like `cliconf.chm` exist on almost all Windows workstation installs.
* **Stability:** Unlike binaries affected by Windows Update (e.g., `kernel32.dll`), CHM content is rarely modified, ensuring the harvested offsets remain valid across different patch levels.

> `python encoder.py -i shellcode.txt -s C:\Windows\Help\mui\0409\cliconf.chm -k 0x4A45B9A3 --xor`

### 3. Update the Loader
Take the generated `alphabetSoup` array and paste it into the PoC loader template. The project supports both **Local Injection** (self) and **Remote Injection** (targeting a separate process).

### 4. Compilation
Compile the loader using the Microsoft C++ compiler (`cl.exe`):
> `cl.exe local-injection.cpp /D"_UNICODE" /D"UNICODE" /W0 /link /OUT:local-injection.exe`
> `cl.exe remote-injection.cpp /D"_UNICODE" /D"UNICODE" /W0 /link /OUT:remote-injection.exe`

### 5. Execution
* **Local:** Run `local-injection.exe`.
* **Remote:** Start your target process (e.g., `notepad.exe`) first, then run `remote-injection.exe`.

---

## Future Improvements
- [ ] **Registry-Based Retrieval:** Store the index array in the Windows Registry to further separate the reconstruction logic from the data.
- [ ] **Dictionary Validation:** Implement a hash-check on the target dictionary file before reconstruction to prevent crashes due to version mismatches.
- [ ] **Position Independent Code (PIC):** Develop a PIC-based decoder to hide the reconstruction process from memory forensic tools.
- [ ] **Remote Delivery:** Enable the 'Alphabet Loader' to fetch the recipe from a remote C2 server or a hidden steganographic image.