#pragma once
#include <windows.h>

typedef enum {
    INTEGRITY_UNKNOWN,
    INTEGRITY_LOW,
    INTEGRITY_MEDIUM,
    INTEGRITY_HIGH,
    INTEGRITY_SYSTEM,
    INTEGRITY_PROTECTED
} IntegrityLevel;

typedef struct LiveProcessNode {
    DWORD pid;                      // Windows Process ID identifier
    DWORD parent_pid;               // Parent Process ID identifier
    IntegrityLevel integrity;       // Extracted from the Token
    char* process_name;             // Dynamic string for the image name
    struct LiveProcessNode* next;   // Pointer to next live node
} LiveProcessNode;