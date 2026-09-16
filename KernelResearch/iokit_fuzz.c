// iokit_fuzz.c — IOKit external method fuzzer for A16 Bionic (iPhone 15)
// Targets AGXMetalA16 GPU driver and IOSurface for kernel r/w primitive research.
//
// Attack surface from sandboxed app (iOS 26.x):
//   • IOAcceleratorFamily2 / AGXMetalA16 — GPU command buffer dispatch, memory allocation
//   • IOSurfaceRoot — shared surface management, cross-process memory
//   • IOHIDEventSystemUserClient — HID/sensor events
//   • AppleEmbeddedNVMeUserClient — NVMe storage (limited from sandbox)
//
// Strategy:
//   1. Enumerate accessible services with IOServiceGetMatchingServices()
//   2. Open each with IOServiceOpen() → IOUserClient
//   3. Iterate selectors 0..max_selector, call IOConnectCallMethod with mutated inputs
//   4. On kr=KERN_SUCCESS with unusual outputs, or on port death → log as interesting
//   5. Struct fuzzing: blast large structs through IOConnectCallStructMethod

#include "iokit_fuzz.h"
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

// kIOMasterPortDefault was renamed kIOMainPortDefault in iOS 15 / macOS 12
// and removed from the iOS SDK. Use MACH_PORT_NULL which is equivalent.
#if !defined(kIOMainPortDefault)
#  define kIOMainPortDefault MACH_PORT_NULL
#endif
#undef  kIOMasterPortDefault
#define kIOMasterPortDefault kIOMainPortDefault

// ── Interesting integer seeds ────────────────────────────────────────────────

static const uint64_t kSeeds[] = {
    0ULL, 1ULL, 2ULL, 3ULL, 4ULL,
    0xFFULL, 0x100ULL, 0xFFFFULL, 0x10000ULL,
    0xFFFFFFFFULL, 0x100000000ULL,
    0x7FFFFFFFULL, 0x80000000ULL,
    0x7FFFFFFFFFFFFFFFULL, 0x8000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL,
    // Likely sizes / offsets that cause integer math bugs
    0x1000ULL, 0x4000ULL, 0x10000ULL, 0x40000000ULL,
    // Common struct offsets on arm64
    0x10ULL, 0x18ULL, 0x20ULL, 0x28ULL, 0x40ULL, 0x80ULL,
    // Pointer-class values that could cause confusion if treated as pointers
    0xFFFFFF8000000000ULL, // kernel text base area
    0x0000000180000000ULL, // typical userland ASLR range for dyld
    // Metal / GPU buffer alignment bait
    0x3FULL, 0x3FULL + 1, (1ULL << 14) - 1, (1ULL << 14),
    // Zero-page bait
    0xDEAD0000ULL, 0xBEEF0000ULL, 0xCAFE0000ULL,
};
#define N_SEEDS (sizeof(kSeeds)/sizeof(kSeeds[0]))

static uint64_t _rand_seed = 0;

static uint64_t _lcg_next(void) {
    _rand_seed = _rand_seed * 6364136223846793005ULL + 1442695040888963407ULL;
    return _rand_seed;
}

static uint64_t _pick_input(void) {
    uint64_t r = _lcg_next();
    // 50% chance: pick a seed value
    if ((r & 1) == 0) {
        return kSeeds[r % N_SEEDS];
    }
    // 25% chance: seed XOR small random delta
    if ((r & 2) == 0) {
        return kSeeds[(_lcg_next()) % N_SEEDS] ^ (_lcg_next() & 0xFF);
    }
    // 25% chance: fully random
    return _lcg_next();
}

// ── Service list ─────────────────────────────────────────────────────────────

static const char *kKnownServices[] = {
    // Primary target — A16 GPU
    "AGXMetalA16",
    "AGXDeviceUserClient",
    // Metal / Accelerator
    "IOAcceleratorFamily2",
    "IOAccelerationUserClient",
    // Surface — cross-process shared memory, great attack surface
    "IOSurfaceRoot",
    // Video scaler — also in AcceleratorFamily
    "AppleM2ScalerCSC",
    // HID
    "IOHIDEventSystemUserClient",
    "IOHIDUserClient",
    // NVMe (limited sandbox access but worth trying)
    "AppleEmbeddedNVMeUserClient",
    // Power management
    "AppleARMPMUUserClient",
    // Misc kernel objects
    "IOMemoryMapUserClient",
    // Display
    "IOMobileFramebuffer",
    NULL
};

// ── Service enumeration ───────────────────────────────────────────────────────

int iokit_enumerate_services(char **log_out) {
    char *buf = malloc(16384);
    if (!buf) return -1;
    buf[0] = '\0';
    int count = 0;

    for (int i = 0; kKnownServices[i] != NULL; i++) {
        CFMutableDictionaryRef match = IOServiceMatching(kKnownServices[i]);
        if (!match) continue;

        io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault, match);
        if (svc == IO_OBJECT_NULL) {
            strlcat(buf, "  NOT_FOUND  ", 16384);
            strlcat(buf, kKnownServices[i], 16384);
            strlcat(buf, "\n", 16384);
            continue;
        }

        // Try to open a user client
        io_connect_t conn = IO_OBJECT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
        char line[256];
        if (kr == KERN_SUCCESS) {
            snprintf(line, sizeof(line), "  OPEN_OK    %s  (conn=0x%x)\n",
                     kKnownServices[i], conn);
            if (conn) IOServiceClose(conn);
            count++;
        } else {
            snprintf(line, sizeof(line), "  OPEN_FAIL  %s  kr=0x%x (%s)\n",
                     kKnownServices[i], kr, mach_error_string(kr));
        }
        strlcat(buf, line, 16384);
        IOObjectRelease(svc);
    }

    *log_out = buf;
    return count;
}

// ── Core scalar fuzzer ────────────────────────────────────────────────────────

int iokit_fuzz_service(const char *service_name,
                       uint32_t    max_selector,
                       uint32_t    rounds_per_selector,
                       FuzzCallback cb,
                       void        *ctx) {
    _rand_seed = (uint64_t)time(NULL) ^ (uint64_t)(uintptr_t)&service_name;

    CFMutableDictionaryRef match = IOServiceMatching(service_name);
    if (!match) return -1;

    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault, match);
    if (svc == IO_OBJECT_NULL) return -1;

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t open_kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);

    if (open_kr != KERN_SUCCESS || conn == IO_OBJECT_NULL) return -1;

    int interesting = 0;

    for (uint32_t sel = 0; sel <= max_selector; sel++) {
        for (uint32_t round = 0; round < rounds_per_selector; round++) {
            // Build fuzzed scalar input — vary count each round
            uint32_t in_cnt  = (uint32_t)(_lcg_next() % 9); // 0..8 scalars
            uint32_t out_cnt = 8;
            uint64_t inputs[8]  = {0};
            uint64_t outputs[8] = {0};

            for (uint32_t j = 0; j < in_cnt; j++) {
                inputs[j] = _pick_input();
            }

            kern_return_t kr = IOConnectCallMethod(
                conn,
                sel,
                inputs,  in_cnt,
                NULL, 0,                // no struct-in
                outputs, &out_cnt,
                NULL, NULL              // no struct-out
            );

            FuzzEntry entry = {0};
            entry.service_name = service_name;
            entry.selector     = sel;
            entry.input_count  = in_cnt;
            entry.kern_return  = (int)kr;
            memcpy(entry.inputs, inputs, sizeof(uint64_t) * in_cnt);

            if (kr == KERN_SUCCESS) {
                // Any successful method call is worth logging on first hit per selector
                if (round == 0) {
                    entry.result = FUZZ_RESULT_OK;
                    snprintf(entry.detail, sizeof(entry.detail),
                             "sel=%-3u OK  out[0..2]=%llx %llx %llx",
                             sel, outputs[0], outputs[1], outputs[2]);
                    interesting++;
                    if (cb) { if (cb(&entry, ctx)) goto done; }
                }
            } else if (kr == kIOReturnNotPrivileged || kr == kIOReturnUnsupported) {
                // Expected sandbox rejection or unimplemented selector — skip
                (void)0;
            } else if (kr == MACH_SEND_INVALID_DEST || kr == MACH_RCV_PORT_DIED) {
                // Port died → service crashed → KERNEL PANIC or driver OOPs
                entry.result = FUZZ_RESULT_PANIC;
                snprintf(entry.detail, sizeof(entry.detail),
                         "PORT_DIED sel=%-3u in_cnt=%u  ***CRASH***", sel, in_cnt);
                interesting++;
                if (cb) cb(&entry, ctx);
                // Service is dead, bail
                goto done;
            } else {
                // Any other error on first round — log it
                if (round == 0) {
                    entry.result = FUZZ_RESULT_ERROR;
                    snprintf(entry.detail, sizeof(entry.detail),
                             "sel=%-3u kr=0x%08x (%s)", sel, kr, mach_error_string(kr));
                    if (cb) { if (cb(&entry, ctx)) goto done; }
                }
            }
        }
    }

done:
    IOServiceClose(conn);
    return interesting;
}

// ── Struct fuzzer ─────────────────────────────────────────────────────────────

int iokit_fuzz_struct_method(const char *service_name,
                             uint32_t    selector,
                             size_t      max_struct_size) {
    CFMutableDictionaryRef match = IOServiceMatching(service_name);
    if (!match) return -1;
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault, match);
    if (svc == IO_OBJECT_NULL) return -1;

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS || conn == IO_OBJECT_NULL) return -1;

    // Patterns to try
    static const uint8_t kPatterns[][4] = {
        {0x00, 0x00, 0x00, 0x00},   // zero
        {0xFF, 0xFF, 0xFF, 0xFF},   // all-ones
        {0x41, 0x41, 0x41, 0x41},   // "AAAA" (classic overflow bait)
        {0xDE, 0xAD, 0xBE, 0xEF},   // deadbeef
        {0x00, 0x00, 0x00, 0x01},   // tiny size
        {0x00, 0x10, 0x00, 0x00},   // 0x1000 as LE32
    };
    int n_patterns = sizeof(kPatterns) / sizeof(kPatterns[0]);

    uint8_t *ibuf = malloc(max_struct_size);
    uint8_t *obuf = malloc(max_struct_size);
    if (!ibuf || !obuf) { free(ibuf); free(obuf); IOServiceClose(conn); return -1; }

    int hits = 0;

    for (size_t sz = 8; sz <= max_struct_size; sz += (sz < 256 ? 8 : 64)) {
        for (int p = 0; p < n_patterns; p++) {
            // Fill input buffer with pattern (tiled)
            for (size_t i = 0; i < sz; i++) {
                ibuf[i] = kPatterns[p][i % 4];
            }

            size_t out_sz = max_struct_size;
            kr = IOConnectCallStructMethod(conn, selector, ibuf, sz, obuf, &out_sz);

            if (kr == KERN_SUCCESS) {
                // Log interesting: method accepted this struct size + pattern
                hits++;
            } else if (kr == MACH_SEND_INVALID_DEST || kr == MACH_RCV_PORT_DIED) {
                // Crash!
                hits += 1000; // heavily weight crashes
                goto struct_done;
            }
        }
    }

struct_done:
    free(ibuf);
    free(obuf);
    IOServiceClose(conn);
    return hits;
}

// ── Convenience wrappers ──────────────────────────────────────────────────────

int iokit_fuzz_agx(FuzzCallback cb, void *ctx) {
    // Try both the class name and the accelerator parent
    int r1 = iokit_fuzz_service("AGXMetalA16", 255, 16, cb, ctx);
    int r2 = iokit_fuzz_service("IOAcceleratorFamily2", 127, 8, cb, ctx);
    return r1 + (r2 > 0 ? r2 : 0);
}

int iokit_fuzz_iosurface(FuzzCallback cb, void *ctx) {
    return iokit_fuzz_service("IOSurfaceRoot", 127, 16, cb, ctx);
}
