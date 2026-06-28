# SysMonitor Subsystem Portfolio

A collection of low-level Windows programs written in native C, tracking the progression from basic user-mode memory management to advanced Win32 process security auditing and kernel-mode concepts.

## 🗺️ Project Roadmap

* **Phase 1: Dynamic Data Engine** — A pure C program focused on manual heap allocation, raw pointer manipulation, and parsing custom file datasets with zero memory leaks.
* **Phase 2: Real-Time Token Analytics** — A live Windows process monitor that modifies its own security privileges (`SeDebugPrivilege`) to read access tokens and audit running process Integrity Levels.
* **Phase 3: The Ring 0 Shield** — *(Pending new hardware)* A Windows kernel driver (`.sys`) that uses process creation callbacks to actively intercept and block forbidden executables from running.

---

## 🛠️ Repository Organization

* **`/MemoryEngine`**: Parses a mock system dataset text file into a dynamic linked list on the heap with strict allocation validation and zero leaks. **(Phase 1)**
* **`/SysMonitor-Explorer`**: Interfaces with the live Win32 subsystem (`kernel32.dll` and `advapi32.dll`) to take process snapshots, open process handles, and extract token details. **(Phase 2)**

## 📋 Requirements

* **Compiler:** MSVC (Visual Studio 2026 / Build Tools)
* **Architecture:** Native x64
* **OS Target:** Windows 10 / 11 Natively (Phase 2 cannot read Windows host tokens from inside WSL)
