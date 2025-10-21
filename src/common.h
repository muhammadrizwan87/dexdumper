#ifndef DEXDUMPER_COMMON_H
#define DEXDUMPER_COMMON_H

// Common header - includes all standard headers and defines shared types
// This is the central include file used throughout the project

#include "config.h"  // Project configuration and macros

// Standard C library headers
#include <stdio.h>   // File I/O operations
#include <stdlib.h>  // Memory allocation, system functions
#include <string.h>  // String manipulation
#include <unistd.h>  // POSIX API (process control)
#include <fcntl.h>   // File control options
#include <sys/mman.h> // Memory management
#include <sys/stat.h> // File status information
#include <android/log.h> // Android logging system
#include <pthread.h> // Threading support
#include <errno.h>   // Error number definitions
#include <time.h>    // Time functions
#include <dirent.h>  // Directory operations
#include <sys/syscall.h> // System calls
#include <math.h>    // Math functions
#include <sys/prctl.h> // Process control
#include <signal.h>  // Signal handling
#include <setjmp.h>  // Non-local jumps (for exception handling)
#include <stdint.h>  // Fixed-width integer types
#include <stddef.h>  // Standard definitions
#include <ctype.h>   // Character type checking and conversion
#include <dlfcn.h>   // Dynamic linking operations
#include <libgen.h>  // Pathname manipulation

/**
 * @brief Represents a memory region from /proc/self/maps
 * 
 * This structure holds information about a contiguous block of memory
 * in the process's address space, including its permissions and backing file.
 */
typedef struct {
    void* start_address;    // Starting virtual address of the region
    void* end_address;      // Ending virtual address of the region
    char permissions[5];    // Memory permissions: rwxsp
    off_t file_offset;      // Offset in the backing file
    unsigned int device_major; // Major device number
    unsigned int device_minor; // Minor device number  
    ino_t inode_number;     // Inode of the backing file
    char path_name[MAX_REGION_NAME]; // Path to backing file or special name
} MemoryRegion;

/**
 * @brief Tracks information about dumped DEX files
 * 
 * Used by the registry system to avoid dumping duplicate files
 * and to maintain metadata about dumped content.
 */
typedef struct {
    ino_t inode_number;     // Inode to identify unique files
    time_t dump_timestamp;  // When the file was dumped
    char file_path[MAX_PATH_LENGTH]; // Where it was saved
    uint8_t sha1_digest[20]; // SHA1 checksum for duplicate detection
} DumpedFileInfo;

/**
 * @brief Result of DEX file detection
 * 
 * Contains location and size information when a DEX file
 * is successfully identified in memory.
 */
typedef struct {
    void* dex_address; // Memory address where DEX file starts
    size_t dex_size;   // Size of the DEX file in bytes
    char version[4];  //version off detector.c
} DexDetectionResult;

#endif
