
# Phase 1: Dynamic Data Engine (`SysMonitor-Core`)

A native C program designed to parse structured data from a text file, load it into a dynamic linked list on the heap, and clean up after itself with zero memory leaks.

## ⚙️ How It Works

1. **Safe File I/O:** Uses secure runtime constraints (`fopen_s`) to open and read a local `processes.txt` dataset line by line.
2. **String Tokenization:** Parses comma-separated values using `strtok_s`, converting string-based security ratings ("Low", "Medium", "High", "System") into a numerical C enum.
3. **Dynamic Memory Allocation:** Allocates nodes on the heap dynamically as it reads the file. Process names are explicitly cloned into dedicated heap buffers using `_strdup`.
4. **Clean Destruction:** Implements a full destruction sequence via a double pointer (`ProcessNode** head`) to safely free the child strings first, free the structure itself, and zero out the root pointer to prevent dangling references.

## 🏗️ Code Architecture

```c
typedef enum {
    INTEGRITY_LOW,
    INTEGRITY_MEDIUM,
    INTEGRITY_HIGH,
    INTEGRITY_SYSTEM
} IntegrityLevel;

typedef struct ProcessNode {
    unsigned long pid;
    unsigned long parent_pid;
    IntegrityLevel integrity;
    char* process_name;         // Heap-allocated string via _strdup
    struct ProcessNode* next;   // Singly-linked list pointer
} ProcessNode;

```

## 🚀 Execution Verification

When running successfully, the engine output follows this sequence:

```text
[+] Initializing SysMonitor-Core Data Engine...
The file 'crt_fopen_s.c' was opened

The file 'processes.txt' was closed
[+] Displaying Active Processes:
PID: 4 | PPID: 0 | Integrity: 3 | Name: System
PID: 124 | PPID: 4 | Integrity: 3 | Name: smss.exe
PID: 816 | PPID: 124 | Integrity: 2 | Name: csrss.exe
PID: 924 | PPID: 816 | Integrity: 2 | Name: wininit.exe
PID: 1004 | PPID: 924 | Integrity: 3 | Name: services.exe
PID: 3120 | PPID: 1004 | Integrity: 1 | Name: explorer.exe
PID: 5440 | PPID: 3120 | Integrity: 1 | Name: chrome.exe
PID: 6112 | PPID: 5440 | Integrity: 0 | Name: untrusted_plugin.exe

[+] Searching for PID 5440... Found! Target Name: chrome.exe
[+] Executing Engine Destruction Lifecycle...
[+] Freeing process node memory for: System
[+] Freeing process node memory for: smss.exe
[+] Freeing process node memory for: csrss.exe
[+] Freeing process node memory for: wininit.exe
[+] Freeing process node memory for: services.exe
[+] Freeing process node memory for: explorer.exe
[+] Freeing process node memory for: chrome.exe
[+] Freeing process node memory for: untrusted_plugin.exe
[+] Heap Cleared. Memory Leak Report: 0 bytes leaked. Clean Exit.

```

