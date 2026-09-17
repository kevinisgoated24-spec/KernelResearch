// KernelResearch-Bridging-Header.h
// Exposes C APIs to Swift

#import "bad_query.h"
#import "iokit_fuzz.h"
#import "metal_trampoline.h"

// vm_region_64 is callable on iOS but Apple marks all *_COUNT macros
// and info structs as "unavailable: structure not supported" in the SDK.
// Define a compatible struct directly so we bypass those restrictions.
#ifndef VM_REGION_COMPAT_DEFINED
#define VM_REGION_COMPAT_DEFINED

#define VM_REGION_EXTENDED_INFO_COMPAT 13  // flavor value from XNU source

struct vm_region_extended_info_compat {
    int            protection;
    unsigned int   user_tag;
    unsigned int   pages_resident;
    unsigned int   pages_shared_now_private;
    unsigned int   pages_swapped_out;
    unsigned int   pages_dirtied;
    unsigned int   ref_count;
    unsigned short shadow_depth;
    unsigned char  external_pager;
    unsigned char  share_mode;
    int            is_submap;
    int            behavior;
    unsigned int   object_id;
    unsigned short user_wired_count;
    unsigned short _pad;
};
typedef struct vm_region_extended_info_compat vm_region_extended_info_compat_t;

#define VM_REGION_EXTENDED_INFO_COMPAT_COUNT \
    ((mach_msg_type_number_t)(sizeof(vm_region_extended_info_compat_t) / sizeof(int)))

#endif
