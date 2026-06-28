# SysMonitor Subsystem Portfolio

A multi-phase native C engineering initiative mapping the progression from user-mode memory management to low-level Windows security internals and token diagnostics.

## 🗺️ Project Roadmap

The architecture scales across three distinct engineering phases:
* **Phase 1: Dynamic Data Engine** — A pure C memory laboratory mastering heap isolation, raw pointer manipulation, and zero-leak lifecycle management.
* **Phase 2: Real-Time Token Analytics** — A live Win32 systems explorer executing token access adjustments (`SeDebugPrivilege`) and auditing mandatory process integrity levels.
* **Phase 3: The Ring 0 Shield** — *(Upcoming Hardware Provisioning)* A native Windows kernel driver (`.sys`) implementing executive subsystem callbacks for active process interception.

---

## 🛠️ Repository Organization

This portfolio is divided into modular, self-contained development workspaces:

* **`/Phase1_MemoryEngine`**: Implements custom singly/doubly linked list engines parsing system datasets with defensive programming constraints.
* **`/Phase2_LiveExplorer`**: Interfaces with the live NT subsystem via `kernel32.dll` and `advapi32.dll` to analyze process tokens.

## 📋 General Requirements
* **Compiler:** MSVC (Microsoft Visual Studio 2026 / Build Tools)
* **Architecture:** Native x64
* **OS Target:** Windows 10/11 Natively (No WSL/Virtualization for Phase 2)
