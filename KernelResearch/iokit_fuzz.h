// iokit_fuzz.h — IOKit external method fuzzer targeting A16 GPU driver
// Target: AGXMetalA16 / IOAcceleratorFamily2 on iPhone 15 (iOS 26.x)

#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Result codes for fuzz callbacks
typedef enum {
    FUZZ_RESULT_OK         = 0,  // method returned without panic
    FUZZ_RESULT_ERROR      = 1,  // kern_return_t != KERN_SUCCESS (may be interesting)
    FUZZ_RESULT_PANIC      = 2,  // service died / port became invalid (kernel panic or crash)
    FUZZ_RESULT_INTERESTING= 3,  // unusual return value worth logging
} FuzzResult;

typedef struct {
    const char *service_name;    // IOKit service class name
    uint32_t    selector;        // external method selector
    uint64_t    inputs[8];       // scalar inputs used
    uint32_t    input_count;     // number of scalar inputs
    int         kern_return;     // returned kr
    FuzzResult  result;
    char        detail[256];     // human-readable summary
} FuzzEntry;

// Callback invoked after each fuzz attempt.
// Return 0 to continue, non-zero to stop fuzzing.
typedef int (*FuzzCallback)(const FuzzEntry *entry, void *ctx);

// Enumerate IOKit services reachable from sandbox and print to log_out (caller frees).
// Returns count of services found.
int iokit_enumerate_services(char **log_out);

// Fuzz all external methods on `service_name` (selectors 0..max_selector).
// For each selector, tries N_ROUNDS of randomly mutated scalar inputs.
// `cb` is called for every attempt (pass NULL to skip callbacks).
// Returns total number of interesting/panic results.
int iokit_fuzz_service(const char *service_name,
                       uint32_t    max_selector,
                       uint32_t    rounds_per_selector,
                       FuzzCallback cb,
                       void        *ctx);

// Convenience: fuzz the primary A16 GPU surface.
// Targets AGXMetalA16, selectors 0..255, 16 rounds each.
int iokit_fuzz_agx(FuzzCallback cb, void *ctx);

// Fuzz IOSurfaceRoot — surface management, often reachable without entitlements.
int iokit_fuzz_iosurface(FuzzCallback cb, void *ctx);

// Fuzz IOMobileFramebuffer — display driver, historically vulnerable (Starlight family).
int iokit_fuzz_framebuffer(FuzzCallback cb, void *ctx);

// Run structured struct-in/struct-out fuzzing on a given service+selector.
// Sends blobs of size `struct_size` filled with patterns: all-zero, all-0xFF,
// canonical integers, and random bytes.
int iokit_fuzz_struct_method(const char *service_name,
                             uint32_t    selector,
                             size_t      max_struct_size);

#ifdef __cplusplus
}
#endif
