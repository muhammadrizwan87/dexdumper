#include "dex_detector.h"
#include <stdint.h>
#include <string.h>


static const char* const DEX_VERSION_SIGS[] = {
    "dex\n035\0", "dex\n036\0", "dex\n037\0", 
    "dex\n038\0", "dex\n039\0", "dex\n040\0"
};
static const size_t DEX_VERSION_COUNT = sizeof(DEX_VERSION_SIGS) / sizeof(DEX_VERSION_SIGS[0]);

/**
 * @brief Fast inline check for DEX magic bytes
 * @param buf Buffer containing potential DEX signature
 * @return 1 if valid DEX signature found, 0 otherwise
 */
static inline int is_valid_dex_signature(const unsigned char* buf) {
    // Quick rejection: check "dex\n" prefix first
    if (buf[0] != 'd' || buf[1] != 'e' || buf[2] != 'x' || buf[3] != '\n') {
        return 0;
    }
    
    // Check version number (035-040 range)
    if (buf[4] != '0' || buf[5] != '3' || (buf[6] < '5' || buf[6] > '9')) {
        // Also check for version 040
        if (!(buf[4] == '0' && buf[5] == '4' && buf[6] == '0')) {
            return 0;
        }
    }
    
    return (buf[7] == '\0'); // Must be null-terminated
}

/**
 * @brief Validates the structure of a potential DEX header
 * 
 * Performs comprehensive validation of DEX header fields to distinguish
 * real DEX files from random memory matching the magic signature.
 * 
 * @param header_start Pointer to the start of memory buffer
 * @param buffer_size Total size of the memory buffer
 * @param header_offset Offset within buffer where header is suspected
 * @return 1 if header is valid, 0 otherwise
 */
int validate_dex_header_structure(const void* header_start, size_t buffer_size, 
                                 size_t header_offset) {
    // Bounds checking with overflow protection
    if (header_offset > buffer_size || 
        buffer_size - header_offset < DEX_HEADER_SIZE) {
        return 0;
    }

    const unsigned char* header_ptr = (const unsigned char*)header_start + header_offset;
    
    // Read and validate file size (offset 0x20)
    uint32_t dex_file_size = 0;
    if (!read_memory_safely(header_ptr + 0x20, &dex_file_size, sizeof(uint32_t))) {
        return 0;
    }

    // Validate DEX file size constraints
    if (dex_file_size < DEX_MIN_FILE_SIZE || dex_file_size > DEX_MAX_FILE_SIZE) {
        LOGW("Invalid DEX file size: %u (range: %d-%d)", 
             dex_file_size, DEX_MIN_FILE_SIZE, DEX_MAX_FILE_SIZE);
        return 0;
    }

    // Ensure claimed size fits in available buffer
    if (dex_file_size > (buffer_size - header_offset)) {
        LOGW("DEX size %u exceeds buffer space %zu", 
             dex_file_size, buffer_size - header_offset);
        return 0;
    }

    // Verify header size field (offset 0x24, should be 0x70)
    uint32_t header_size_val = 0;
    if (!read_memory_safely(header_ptr + 0x24, &header_size_val, sizeof(uint32_t))) {
        return 0;
    }
    
    if (header_size_val != DEX_HEADER_SIZE) {
        LOGW("DEX header size mismatch: 0x%x (expected 0x%x)", 
             header_size_val, DEX_HEADER_SIZE);
        return 0;
    }

    // Check endian tag (offset 0x28, should be 0x12345678)
    uint32_t endian_tag = 0;
    if (!read_memory_safely(header_ptr + 0x28, &endian_tag, sizeof(uint32_t))) {
        return 0;
    }
    
    if (endian_tag != 0x12345678U) {
        LOGW("Invalid DEX endian tag: 0x%08x", endian_tag);
        return 0;
    }

    // Validate link section (offset 0x2C-0x30)
    uint32_t link_size = 0, link_offset = 0;
    if (!read_memory_safely(header_ptr + 0x2C, &link_size, sizeof(uint32_t)) ||
        !read_memory_safely(header_ptr + 0x30, &link_offset, sizeof(uint32_t))) {
        return 0;
    }
    
    if (link_size > 0) {
        if (link_offset >= dex_file_size || 
            link_offset + link_size > dex_file_size) {
            LOGW("Invalid DEX link section: offset=%u, size=%u", link_offset, link_size);
            return 0;
        }
    }

    // Validate map section (offset 0x34)
    uint32_t map_offset = 0;
    if (!read_memory_safely(header_ptr + 0x34, &map_offset, sizeof(uint32_t))) {
        return 0;
    }
    
    if (map_offset >= dex_file_size) {
        LOGW("Invalid DEX map offset: %u", map_offset);
        return 0;
    }

    // Validate string table (offset 0x38-0x3C)
    uint32_t string_ids_size = 0, string_ids_off = 0;
    if (!read_memory_safely(header_ptr + 0x38, &string_ids_size, sizeof(uint32_t)) ||
        !read_memory_safely(header_ptr + 0x3C, &string_ids_off, sizeof(uint32_t))) {
        return 0;
    }
    
    if (string_ids_size > 0) {
        // Each string ID is 4 bytes
        uint64_t string_table_end = (uint64_t)string_ids_off + 
                                    ((uint64_t)string_ids_size * 4);
        if (string_ids_off >= dex_file_size || string_table_end > dex_file_size) {
            LOGW("Invalid string table: offset=%u, size=%u", string_ids_off, string_ids_size);
            return 0;
        }
    }

    // Validate type IDs section (offset 0x40-0x44)
    uint32_t type_ids_size = 0, type_ids_off = 0;
    if (!read_memory_safely(header_ptr + 0x40, &type_ids_size, sizeof(uint32_t)) ||
        !read_memory_safely(header_ptr + 0x44, &type_ids_off, sizeof(uint32_t))) {
        return 0;
    }
    
    if (type_ids_size > 0) {
        uint64_t type_table_end = (uint64_t)type_ids_off + ((uint64_t)type_ids_size * 4);
        if (type_ids_off >= dex_file_size || type_table_end > dex_file_size) {
            return 0;
        }
    }

    // Validate proto IDs section (offset 0x48-0x4C)
    uint32_t proto_ids_size = 0, proto_ids_off = 0;
    if (!read_memory_safely(header_ptr + 0x48, &proto_ids_size, sizeof(uint32_t)) ||
        !read_memory_safely(header_ptr + 0x4C, &proto_ids_off, sizeof(uint32_t))) {
        return 0;
    }
    
    if (proto_ids_size > 0) {
        uint64_t proto_table_end = (uint64_t)proto_ids_off + ((uint64_t)proto_ids_size * 12);
        if (proto_ids_off >= dex_file_size || proto_table_end > dex_file_size) {
            return 0;
        }
    }

    // Validate method IDs section (offset 0x58-0x5C)
    uint32_t method_ids_size = 0, method_ids_off = 0;
    if (!read_memory_safely(header_ptr + 0x58, &method_ids_size, sizeof(uint32_t)) ||
        !read_memory_safely(header_ptr + 0x5C, &method_ids_off, sizeof(uint32_t))) {
        return 0;
    }
    
    if (method_ids_size > 0) {
        uint64_t method_table_end = (uint64_t)method_ids_off + ((uint64_t)method_ids_size * 8);
        if (method_ids_off >= dex_file_size || method_table_end > dex_file_size) {
            return 0;
        }
    }

    return 1; // All validations passed
}

/**
 * @brief Scans memory for DEX file signatures with optimized algorithm
 * 
 * Uses efficient scanning with alignment optimization and early rejection.
 * 
 * @param scan_start Starting address to scan from
 * @param scan_size Size of memory region to scan
 * @param max_scan_limit Maximum bytes to scan (for performance)
 * @param detection_result Output parameter for detection results
 * @return 1 if DEX found, 0 otherwise
 */
int scan_for_dex_signature(const void* scan_start, size_t scan_size, 
                          size_t max_scan_limit, DexDetectionResult* detection_result) {
    if (scan_start == NULL || detection_result == NULL || scan_size < 8) {
        return 0;
    }
    
    // Calculate actual scan limit
    size_t actual_limit = (max_scan_limit < scan_size) ? max_scan_limit : scan_size;
    if (actual_limit < DEX_HEADER_SIZE) {
        return 0;
    }
    
    const unsigned char* scan_ptr = (const unsigned char*)scan_start;
    unsigned char sig_buf[8];
    
    // Scan with 4-byte alignment for better performance
    // DEX files are typically 4-byte aligned in memory
    for (size_t offset = 0; offset <= actual_limit - 8; offset += 4) {
        // Read potential signature
        if (!read_memory_safely(scan_ptr + offset, sig_buf, 8)) {
            continue;
        }
        
        // Fast signature validation
        if (!is_valid_dex_signature(sig_buf)) {
            continue;
        }
        
        VLOGD("DEX signature candidate at offset 0x%zx", offset);
        
        // Validate complete header structure
        if (!validate_dex_header_structure(scan_start, scan_size, offset)) {
            LOGW("DEX signature found but validation failed at offset 0x%zx", offset);
            continue;
        }
        
        // Read validated file size
        uint32_t file_size = 0;
        if (!read_memory_safely(scan_ptr + offset + 0x20, &file_size, sizeof(uint32_t))) {
            continue;
        }
        
        // Populate result
        detection_result->dex_address = (void*)(scan_ptr + offset);
        detection_result->dex_size = file_size;
        
        // Extract version info
        memcpy(detection_result->version, sig_buf + 4, 3);
        detection_result->version[3] = '\0';
        
        LOGI("Valid DEX detected: addr=%p, size=%u, version=%s", 
             detection_result->dex_address, file_size, detection_result->version);
        
        return 1;
    }
    
    return 0;
}

/**
 * @brief Scans a memory region for standard DEX files
 * 
 * @param region_start Start of memory region to scan
 * @param region_size Size of memory region
 * @param detection_result Output for detection results
 * @return 1 if DEX found, 0 otherwise
 */
int scan_region_for_dex_files(const void* region_start, size_t region_size, 
                             DexDetectionResult* detection_result) {
    if (region_size < DEX_HEADER_SIZE) {
        return 0;
    }
    
    size_t scan_limit = (region_size > DEFAULT_SCAN_LIMIT) ? 
                        DEFAULT_SCAN_LIMIT : region_size;
    
    return scan_for_dex_signature(region_start, region_size, scan_limit, detection_result);
}

/**
 * @brief Scans OAT containers for embedded DEX files
 * 
 * OAT files are Android's optimized ART format containing embedded DEX.
 * 
 * @param region_start Start of memory region
 * @param region_size Size of memory region  
 * @param detection_result Output for detection results
 * @return 1 if DEX found in OAT, 0 otherwise
 */
int scan_region_for_oat_dex_files(const void* region_start, size_t region_size, 
                                 DexDetectionResult* detection_result) {
    if (region_size < 8) {
        return 0;
    }
    
    unsigned char magic[4];
    if (!read_memory_safely(region_start, magic, 4)) {
        return 0;
    }
    
    // Check for OAT magic: "oat\n"
    if (memcmp(magic, "oat\n", 4) != 0) {
        return 0;
    }
    
    VLOGD("OAT container detected, scanning for embedded DEX");
    
    // OAT header is typically followed by DEX within first 128KB
    size_t oat_scan_limit = (region_size < 128 * 1024) ? region_size : 128 * 1024;
    
    return scan_for_dex_signature(region_start, region_size, oat_scan_limit, detection_result);
}

/**
 * @brief Scans for VDEX (Verified DEX) files
 * 
 * VDEX files contain pre-verified DEX bytecode used by ART.
 * 
 * @param region_start Start of memory region
 * @param region_size Size of memory region
 * @param detection_result Output for detection results
 * @return 1 if DEX found in VDEX, 0 otherwise
 */
int scan_region_for_vdex_files(const void* region_start, size_t region_size,
                              DexDetectionResult* detection_result) {
    if (region_size < 8) {
        return 0;
    }
    
    unsigned char magic[4];
    if (!read_memory_safely(region_start, magic, 4)) {
        return 0;
    }
    
    // Check for VDEX magic: "vdex"
    if (memcmp(magic, "vdex", 4) != 0) {
        return 0;
    }
    
    VLOGD("VDEX container detected, scanning for embedded DEX");
    
    // VDEX header contains DEX sections, scan first 256KB
    size_t vdex_scan_limit = (region_size < 256 * 1024) ? region_size : 256 * 1024;
    
    return scan_for_dex_signature(region_start, region_size, vdex_scan_limit, detection_result);
}

/**
 * @brief Performs comprehensive DEX detection using multiple strategies
 * 
 * Tries different detection methods to find DEX files in various formats.
 * 
 * @param region_start Start of memory region to scan
 * @param region_size Size of memory region
 * @param detection_result Output for detection results
 * @return 1 if DEX found, 0 otherwise
 */
int perform_comprehensive_dex_detection(const void* region_start, size_t region_size, 
                                       DexDetectionResult* detection_result) {
    if (region_start == NULL || detection_result == NULL || region_size == 0) {
        return 0;
    }
    
   
    typedef int (*DetectorFunc)(const void*, size_t, DexDetectionResult*);
    
    static const struct {
        const char* name;
        DetectorFunc func;
    } strategies[] = {
        {"standard DEX", scan_region_for_dex_files},
        {"OAT container", scan_region_for_oat_dex_files},
        {"VDEX container", scan_region_for_vdex_files}
    };
    
    const size_t strategy_count = sizeof(strategies) / sizeof(strategies[0]);
    
    
    for (size_t i = 0; i < strategy_count; i++) {
        VLOGD("Trying %s detection strategy", strategies[i].name);
        
        if (strategies[i].func(region_start, region_size, detection_result)) {
            LOGI("DEX detected via %s strategy", strategies[i].name);
            return 1;
        }
    }
    
    VLOGD("No DEX found after trying all detection strategies");
    return 0;
}
