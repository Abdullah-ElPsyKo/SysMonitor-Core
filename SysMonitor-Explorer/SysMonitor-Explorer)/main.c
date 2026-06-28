#include <stdio.h>
#include <Windows.h>
#include "blueprint.h"
#include <tlhelp32.h>

void ErrorExit()
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	DWORD dw = GetLastError();

	if (FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL) == 0) {
		MessageBox(NULL, TEXT("FormatMessage failed"), TEXT("Error"), MB_OK);
		ExitProcess(dw);
	}

	MessageBox(NULL, (LPCTSTR)lpMsgBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	ExitProcess(dw);
}

BOOL EnableSeDebugPrivilege(void) {
	HANDLE current_proc = GetCurrentProcess();
	HANDLE token_handle = NULL;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	// 1. Open token with explicit query and adjust rights
	if (OpenProcessToken(current_proc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle) == FALSE)
	{
		return FALSE;
	}

	// 2. Use the generic wrapper to auto-match your project's character set (ANSI vs Unicode)
	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid) == FALSE)
	{
		CloseHandle(token_handle);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// 3. Clear the error pipeline
	SetLastError(0);

	// 4. Fire the modification
	AdjustTokenPrivileges(token_handle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	// 5. Check if AdjustTokenPrivileges failed your request
	if (GetLastError() != ERROR_SUCCESS)
	{
		CloseHandle(token_handle);
		return FALSE;
	}

	CloseHandle(token_handle);
	return TRUE;
}




LiveProcessNode* snapshot_system_processes(void) {
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	// --- LINKED LIST TRACKERS ---
	LiveProcessNode* head = NULL;
	LiveProcessNode* tail = NULL;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("[-] Error: CreateToolhelp32Snapshot failed.\n");
		return(NULL);
	}

	// MANDATORY WIN32 STEP: Populate structure size initialization
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("[-] Error: Process32First"); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(NULL);
	}

	do
	{
		int required_bytes = WideCharToMultiByte(
			CP_ACP,                 // CodePage: Standard ANSI conversion
			0,                      // Flags: Default settings
			pe32.szExeFile,         // Source: The raw Wide String from the OS snapshot
			-1,                     // Tell Windows to read until it hits the wide null-terminator
			NULL,                   // Target: NULL, because we don't have a buffer yet!
			0,                      // Target Size: 0, which signals we are only querying the size
			NULL, NULL              // Default character system settings
		);

		if (required_bytes == 0) {
			// Handling a critical translation failure defensively
			printf("[-] Failed to calculate string conversion size.\n");
			continue;
		}

		// 2. Allocate the exact amount of 1-byte memory on the Heap
		char* normal_process_name = (char*)malloc(required_bytes);
		if (normal_process_name == NULL) {
			printf("[-] Heap allocation failure for process name.\n");
			continue;
		}

		// 3. Perform the actual data translation (The Execution Pass)
		WideCharToMultiByte(
			CP_ACP,
			0,
			pe32.szExeFile,
			-1,
			normal_process_name,    // Target: Our fresh, 1-byte heap allocation box
			required_bytes,         // Target Size: The exact size we allocated
			NULL, NULL
		);

		LiveProcessNode* new_node = (LiveProcessNode*)malloc(sizeof(LiveProcessNode));

		if (new_node == NULL)
		{
			free(normal_process_name);
			continue;
		}

		new_node->pid = pe32.th32ProcessID;
		new_node->parent_pid = pe32.th32ParentProcessID;
		new_node->integrity = extract_integrity_level(pe32.th32ProcessID);
		new_node->process_name = normal_process_name;
		new_node->next = NULL;

		if (head == NULL)
		{
			head = new_node;
			tail = new_node;
		}
		else
		{
			tail->next = new_node;
			tail = new_node;
		}

		//printf("\n\n=====================================================");
		//printf("\nPROCESS NAME:  %s", normal_process_name);
		//printf("\n-------------------------------------------------------");


		//// Display the raw identifiers extracted straight from the kernel tables
		//printf("\n  Process ID        = %lu (0x%08X)", pe32.th32ProcessID, pe32.th32ProcessID);
		//printf("\n  Parent process ID = %lu (0x%08X)", pe32.th32ParentProcessID, pe32.th32ParentProcessID);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return head;
}

IntegrityLevel extract_integrity_level(DWORD pid)
{
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	DWORD dwIntegrityLevel = 0;
	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	DWORD dwLength = 0;

	// Initialize our tracking variable
	IntegrityLevel result = INTEGRITY_UNKNOWN;

	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProcess == NULL) {
		return INTEGRITY_UNKNOWN; // Return 0 to indicate "Access Denied / Unknown"
	}

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		CloseHandle(hProcess);
		return INTEGRITY_UNKNOWN;
	}

	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);
	if (dwLength == 0) {
		CloseHandle(hToken);
		CloseHandle(hProcess);
		return INTEGRITY_UNKNOWN;
	}

	pTIL = (PTOKEN_MANDATORY_LABEL)malloc(dwLength);
	if (pTIL == NULL) {
		CloseHandle(hToken);
		CloseHandle(hProcess);
		return INTEGRITY_UNKNOWN;
	}

	// 5. Second call extracts the actual security label structure
	if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength)) {
		// Extract the sub-authority value (this is where the RID lives)
		dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
			(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

		switch (dwIntegrityLevel) {
		case SECURITY_MANDATORY_UNTRUSTED_RID:  result = INTEGRITY_UNKNOWN;   break;
		case SECURITY_MANDATORY_LOW_RID:        result = INTEGRITY_LOW;       break;
		case SECURITY_MANDATORY_MEDIUM_RID:     result = INTEGRITY_MEDIUM;    break;
		case SECURITY_MANDATORY_HIGH_RID:       result = INTEGRITY_HIGH;      break;
		case SECURITY_MANDATORY_SYSTEM_RID:     result = INTEGRITY_SYSTEM;    break;
		case SECURITY_MANDATORY_PROTECTED_PROCESS_RID: result = INTEGRITY_PROTECTED; break;
		default:                                result = INTEGRITY_UNKNOWN;   break;
		}
	}
	
	// Clean up all local handles and heap allocations before returning
	free(pTIL);
	CloseHandle(hToken);
	CloseHandle(hProcess);

	return result;
}

void print_live_dashboard(LiveProcessNode* head) {
	// Read and audit the linked list from the beginning to the end
	LiveProcessNode* current = head;
	while (current != NULL)
	{
		printf("\n=====================================================");
		printf("\nPROCESS NAME:  %s", current->process_name);
		printf("\n-------------------------------------------------------");
		printf("\n  Process ID        = %u (0x%08X)", current->pid, current->pid);
		printf("\n  Parent process ID = %u (0x%08X)", current->parent_pid, current->parent_pid);

		char* integrity;

		switch (current->integrity) {
		case INTEGRITY_LOW:
			integrity = "LOW";
			break;
		case INTEGRITY_MEDIUM:    // default user
			integrity = "MEDIUM";
			break;
		case INTEGRITY_HIGH:      // admin
			integrity = "HIGH";
			break;
		case INTEGRITY_SYSTEM:    // NT AUTHORITY\SYSTEM
			integrity = "SYSTEM";
			break;
		case INTEGRITY_PROTECTED:
			integrity = "PROTECTED";
			break;
		default:
			integrity = "UNKNOWN / ACCESS DENIED";
			break;
		}

		if (current->integrity == 0) {
			printf("\n  Integrity Level   = [!] ACCESS DENIED / UNKNOWN");
		}
		else {
			printf("\n  Integrity Level   = [+] %s", integrity);
		}

		current = current->next;
	}
}

void free_live_tree(LiveProcessNode* head)
{
	LiveProcessNode* current = head;
	while (current != NULL) {
		LiveProcessNode* next_node = current->next;

		printf("\n[+] Freeing live process node memory for: %s", current->process_name);

		free(current->process_name);
		free(current);
		current = next_node;
	}
}


void main()
{
	printf("[+] Initializing SysMonitor-Explorer Security Subsystem...\n");
	printf("[+] Attempting to acquire SeDebugPrivilege...\n");

	if (EnableSeDebugPrivilege() == FALSE)
	{
		printf("[-] Critical: Failed to acquire SeDebugPrivilege.\n");
		ErrorExit();
	}

	printf("[+] SUCCESS: SeDebugPrivilege is now fully enabled in our process token.\n\n");

	// 1. Capture the completed heap database chain
	LiveProcessNode* list_head = snapshot_system_processes();

	// 2. Render the security landscape
	print_live_dashboard(list_head);

	// 3. Destruct the tracking data cleanly
	free_live_tree(list_head);
	list_head = NULL; // Zero out the root pointer

	printf("\n\n[+] Audit Complete. Press ENTER to exit the engine...");

	(void)getchar();

	return;
}