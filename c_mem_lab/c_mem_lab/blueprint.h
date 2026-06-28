#pragma once
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
    char* process_name;         // Explicitly allocated pointer to string
    struct ProcessNode* next;   // Pointer to next node in heap memory
} ProcessNode;
