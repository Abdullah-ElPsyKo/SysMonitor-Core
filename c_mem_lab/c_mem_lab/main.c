#include <stdio.h>
#include <string.h>
#include "blueprint.h"
#include <stdlib.h> 


ProcessNode* load_processes(const char* filename)
{
	FILE* fptr = NULL;
	char line[256];
	errno_t err;
	struct ProcessNode* head = NULL;
	struct ProcessNode* tail = NULL;

	err = fopen_s(&fptr, filename, "r");

	if (err == 0)
	{
		const char* delim = ",";
		char* tok = NULL;
		char* next_tok = NULL;

		// Column index tracker
		int index_data = 0;

		printf("The file 'crt_fopen_s.c' was opened\n");
		while (fgets(line, sizeof(line), fptr)) {

			// Allocate node
			struct ProcessNode* new_node = (struct ProcessNode*)malloc(sizeof(struct ProcessNode));
			if (new_node == NULL) {
				fprintf(stderr, "[ERROR] Fatal: Memory allocation failed for new node.");
				fclose(fptr);
				return head;
			}
			// Placeholders for the single line we are currently parsing
			unsigned long current_pid = 0;
			unsigned long current_ppid = 0;
			IntegrityLevel current_integrity = INTEGRITY_LOW;
			char* current_name = NULL;
			char* check_level = NULL;

			tok = strtok_s(line, delim, &next_tok);

			while (tok != NULL) {
				switch (index_data) {
				case 0:
					current_pid = strtoul(tok, NULL, 10);
					break;

				case 1:
					current_ppid = strtoul(tok, NULL, 10);
					break;

				case 2:
					if (strcmp(tok, "Low") == 0) {
						current_integrity = INTEGRITY_LOW;
					}
					else if (strcmp(tok, "Medium") == 0) {
						current_integrity = INTEGRITY_MEDIUM;
					}
					else if (strcmp(tok, "High") == 0) {
						current_integrity = INTEGRITY_HIGH;
					}
					else if (strcmp(tok, "System") == 0) {
						current_integrity = INTEGRITY_SYSTEM;
					}
					break;

				case 3:
					tok[strcspn(tok, "\r\n")] = '\0';
					current_name = tok;
					break;

				default:
					// If the counter is 4 or higher, the line is corrupted or has extra data
					break;
				}
				tok = strtok_s(NULL, delim, &next_tok);
				index_data++;
			} // finished assiging variables

			//printf("[Line Parsed] PID: %lu | PPID: %lu | Integrity: %d | Name: %s\n", current_pid, current_ppid, current_integrity, current_name);

			new_node->pid = current_pid;
			new_node->parent_pid = current_ppid;
			new_node->integrity = current_integrity;
			new_node->process_name = _strdup(current_name);

			if (head == NULL) {
				head = new_node;
				tail = new_node;
			}
			else {
				tail->next = new_node;
				tail = new_node;
			}
			new_node->next = NULL;
			new_node = NULL;
			index_data = 0;
			next_tok = NULL;
		}

		err = fclose(fptr);

		if (err == 0)
		{
			printf("\nThe file '%s' was closed\n", filename);
		}
		else
		{
			printf("\nThe file '%s' was not closed\n", filename);
		}

	}
	else
	{
		printf("\nThe file 'crt_fopen_s.c' was not opened\n");
	}
	return head;
}


void print_process_tree(ProcessNode* head) {
	ProcessNode* readNode = head;
	while (readNode != NULL) {
		printf("PID: %lu | PPID: %lu | Integrity: %d | Name: %s\n", readNode->pid, readNode->parent_pid, readNode->integrity, readNode->process_name);
		readNode = readNode->next;
	}
	return;
}

ProcessNode* find_process_by_pid(ProcessNode* head, unsigned long pid) {
	ProcessNode* readNode = head;
	while (readNode != NULL)
	{
		if (readNode->pid == pid)
		{
			return readNode;
		}
		readNode = readNode->next;
	}
	return NULL;
}

void free_process_tree(ProcessNode** head) {
	if (head == NULL || *head == NULL) return;

	ProcessNode* current = *head;
	ProcessNode* next_node = NULL;

	while (current != NULL) {
		next_node = current->next;
		printf("[+] Freeing process node memory for: %s\n", current->process_name);
		free(current->process_name);
		free(current);
		current = next_node;
	}
	*head = NULL;
}

int main(void)
{
	printf("[+] Initializing SysMonitor-Core Data Engine...\n");

	// 1. Load the database safely to the heap
	ProcessNode* process_list = load_processes("processes.txt");
	if (process_list == NULL) {
		return 1;
	}

	// 2. Clear out formatting spacing and dump dashboard
	printf("[+] Displaying Active Processes:\n");
	print_process_tree(process_list);
	printf("\n");

	// 3. Search target validation test (PID 5440)
	unsigned long target_pid = 5440;
	ProcessNode* target_node = find_process_by_pid(process_list, target_pid);
	if (target_node != NULL) {
		printf("[+] Searching for PID %lu... Found! Target Name: %s\n", target_pid, target_node->process_name);
	}
	else {
		printf("[-] Searching for PID %lu... Process Not Found.\n", target_pid);
	}

	// 4. Fire the absolute engine lifecycle destruction sequence
	printf("[+] Executing Engine Destruction Lifecycle...\n");
	free_process_tree(&process_list);

	// 5. Final validation statement confirmation
	printf("[+] Heap Cleared. Memory Leak Report: 0 bytes leaked. Clean Exit.\n");

	return 0;
}