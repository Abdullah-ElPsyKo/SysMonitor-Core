# Phase 2: Real-Time Process Token Analytics Engine (`SysMonitor-Explorer`)

An upgrade from Phase 1 that drops the static text file and interfaces directly with the live Windows operating system. The program escalates its own privileges, takes a snapshot of all running processes, and inspects their access tokens to extract real-time security integrity levels.

## ⚙️ How It Works

1. **Token Privilege Escalation:** Modifies its own process token using `OpenProcessToken` and `AdjustTokenPrivileges` to enable `SE_DEBUG_NAME`. This grants the application permission to inspect high-privilege system processes that are normally restricted.
2. **Live System Snapshot:** Uses the Windows toolhelp library (`CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`) to capture a live view of the operating system thread space.
3. **Double-Hop Memory Allocation:**
   * **Strings:** Calls `WideCharToMultiByte` twice per process—once to get the exact buffer size needed for the executable name, and a second time to safely write it into a custom `malloc` heap allocation.
   * **Tokens:** Calls `GetTokenInformation` twice to fetch the exact buffer size required for variable-sized Security Identifiers (SIDs) without risking buffer overflows.
4. **Defensive Handle Hygiene:** Every opened process or token handle is tracked and closed using `CloseHandle` to prevent kernel resource leaks during long runtime loops.

## 🏗️ Code Architecture

```c
typedef enum {
    INTEGRITY_LOW,
    INTEGRITY_MEDIUM,
    INTEGRITY_HIGH,
    INTEGRITY_SYSTEM,
    INTEGRITY_PROTECTED,
    INTEGRITY_UNKNOWN
} IntegrityLevel;

typedef struct LiveProcessNode {
    DWORD pid;
    DWORD parent_pid;
    IntegrityLevel integrity;
    char* process_name;
    struct LiveProcessNode* next;
} LiveProcessNode;

```

## 🚀 Execution Verification

The live console application maps your actual system components natively:

```text
[+] Initializing SysMonitor-Explorer Security Subsystem...
[+] Attempting to acquire SeDebugPrivilege...
[+] SUCCESS: SeDebugPrivilege is now fully enabled in our process token.

=====================================================
PROCESS NAME:  System
-----------------------------------------------------
  Process ID        = 4 (0x00000004)
  Parent process ID = 0 (0x00000000)
  Integrity Level   = [+] SYSTEM
=====================================================
PROCESS NAME:  lsass.exe
-----------------------------------------------------
  Process ID        = 824 (0x00000338)
  Parent process ID = 144 (0x00000090)
  Integrity Level   = [+] SYSTEM

[+] Freeing live process node memory for: System
[+] Freeing live process node memory for: lsass.exe


[+] Audit Complete. Press ENTER to exit the engine...

```

```
