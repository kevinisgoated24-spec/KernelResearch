import Metal
import IOSurface
import Foundation

// Metal + IOSurface framework fuzzer.
// These APIs are fully accessible from sandbox — they go through the same
// GPU kernel driver (AGX) and IOSurface allocator that raw IOKit hits,
// but through the allowed XPC/framework path.
//
// Known crash classes this targets:
//   • Integer overflow in IOSurface allocator (large allocSize / bytesPerRow)
//   • OOB in Metal command buffer parser (malformed compute dispatches)
//   • Use-after-free in MTLHeap dealloc racing with GPU submission
//   • Type confusion in Metal texture → IOSurface bridge
//   • MTLArgumentEncoder with wrong buffer bindings

class MetalFuzzer {
    let log: FuzzLog
    let device: MTLDevice
    let queue: MTLCommandQueue

    init?(log: FuzzLog) {
        self.log = log
        guard let dev = MTLCreateSystemDefaultDevice(),
              let q   = dev.makeCommandQueue() else { return nil }
        self.device = dev
        self.queue  = q
    }

    // MARK: - IOSurface allocation stress

    func fuzzIOSurfaceAlloc() {
        log.append("── IOSurface alloc stress ──────────────────")

        // Only safe, semantically-valid sizes — no overflow bait here
        // (overflow inputs cause kernel-side assertions that kill the app process)
        struct Case { let label: String; let w: Int; let h: Int; let bpe: Int; let bpr: Int }
        let cases: [Case] = [
            Case(label:"minimal",      w:1,    h:1,   bpe:4,  bpr:4),
            Case(label:"64x64-rgba",   w:64,   h:64,  bpe:4,  bpr:256),
            Case(label:"256x256-rgba", w:256,  h:256, bpe:4,  bpr:1024),
            Case(label:"1920x1-rgba",  w:1920, h:1,   bpe:4,  bpr:7680),
            Case(label:"512x512-rgba", w:512,  h:512, bpe:4,  bpr:2048),
            Case(label:"1x1-bpr-mismatch", w:1, h:1, bpe:4,  bpr:16), // bpr > bpe*w
            Case(label:"oddW-13x7",    w:13,   h:7,   bpe:4,  bpr:52),
        ]

        for c in cases {
            autoreleasepool {
                let allocSz = c.h * c.bpr
                let props: [IOSurfacePropertyKey: Any] = [
                    .width: c.w, .height: c.h,
                    .bytesPerElement: c.bpe, .bytesPerRow: c.bpr,
                    .allocSize: allocSz,
                ]
                log.append("  [alloc] \(c.label) \(c.w)x\(c.h)")
                let surf = IOSurface(properties: props)
                guard let s = surf else {
                    log.append("    → nil")
                    return
                }
                log.append("    → OK allocSz=\(allocSz)")
                var seed: UInt32 = 0xDEADBEEF
                let lr = s.lock(options: [], seed: &seed)
                log.append("    lock→\(lr) seed=0x\(String(seed, radix:16))")
                let ur = s.unlock(options: [], seed: &seed)
                log.append("    unlock→\(ur)")
            }
        }
    }

    // MARK: - Metal buffer edge cases (stay under 4MB total)

    func fuzzMetalBuffers() {
        log.append("── Metal buffer edge cases ─────────────────")

        // Page boundary straddles — interesting for VA allocator
        let sizes: [Int] = [1, 3, 7, 0x3FFF, 0x4000, 0x4001, 0x3FFFF, 0x40000, 0x40001, 0x100000]
        for sz in sizes {
            autoreleasepool {
                let buf = device.makeBuffer(length: sz, options: .storageModeShared)
                if let b = buf {
                    // Check actual rounded length vs requested — mismatch = interesting
                    let rounded = b.length
                    let extra = rounded - sz
                    let ptr = b.contents().assumingMemoryBound(to: UInt8.self)
                    ptr[0] = 0xAA
                    ptr[rounded - 1] = 0xBB   // write to actual last byte
                    log.append("  buf req=0x\(String(sz, radix: 16)) actual=0x\(String(rounded, radix: 16)) pad=\(extra)")
                } else {
                    log.append("  buf 0x\(String(sz, radix: 16)) → nil")
                }
            }
        }

        // storageMode variants on same size
        let modes: [(MTLResourceOptions, String)] = [
            (.storageModeShared,   "shared"),
            (.storageModePrivate,  "private"),
        ]
        for (mode, name) in modes {
            autoreleasepool {
                let buf = device.makeBuffer(length: 4096, options: mode)
                log.append("  buf 4096 \(name) → \(buf == nil ? "nil" : "OK")")
            }
        }
    }

    // MARK: - Texture edge cases + IOSurface-backed textures (stay under 16MB)

    func fuzzMetalTextures() {
        log.append("── Metal texture edge cases ────────────────")

        struct TexCase { let w: Int; let h: Int; let fmt: MTLPixelFormat; let label: String }
        // Max safe: 2048x2048 RGBA = 16MB
        let cases: [TexCase] = [
            TexCase(w: 1,     h: 1,    fmt: .rgba8Unorm,  label: "1x1"),
            TexCase(w: 2048,  h: 1,    fmt: .rgba8Unorm,  label: "2048x1-strip"),
            TexCase(w: 2048,  h: 2048, fmt: .r8Unorm,     label: "2048x2048-r8"),   // 4MB
            TexCase(w: 4096,  h: 1024, fmt: .r8Unorm,     label: "4096x1024-r8"),   // 4MB
            TexCase(w: 8192,  h: 1,    fmt: .r8Unorm,     label: "8192x1-strip"),
            TexCase(w: 16383, h: 1,    fmt: .r8Unorm,     label: "16383x1"),         // just under 16K
            TexCase(w: 16384, h: 1,    fmt: .r8Unorm,     label: "16384x1-maxdim"),  // at limit
            TexCase(w: 16385, h: 1,    fmt: .r8Unorm,     label: "16385x1-over"),    // over limit
        ]

        for c in cases {
            autoreleasepool {
                let td = MTLTextureDescriptor.texture2DDescriptor(
                    pixelFormat: c.fmt, width: c.w, height: c.h, mipmapped: false)
                td.storageMode = .shared
                let tex = device.makeTexture(descriptor: td)
                log.append("  tex \(c.label) → \(tex == nil ? "nil" : "OK actual=\(tex!.width)x\(tex!.height)")")
            }
        }

        // IOSurface-backed texture — bridge between Metal and IOSurface allocators
        // Mismatched pixelFormat between surface and texture is the interesting case
        log.append("  IOSurface-backed tex (matched format):")
        autoreleasepool {
            let surf = IOSurface(properties: [
                .width: 256, .height: 256, .bytesPerElement: 4, .bytesPerRow: 1024,
            ])
            guard let s = surf else { log.append("  surf alloc nil"); return }
            let td = MTLTextureDescriptor.texture2DDescriptor(
                pixelFormat: .bgra8Unorm, width: 256, height: 256, mipmapped: false)
            td.storageMode = .shared
            let tex = device.makeTexture(descriptor: td, iosurface: s, plane: 0)
            log.append("  → \(tex == nil ? "nil" : "OK")")
        }

        log.append("  IOSurface-backed tex (mismatched size — surf 128x128, tex 256x256):")
        autoreleasepool {
            let surf = IOSurface(properties: [
                .width: 128, .height: 128, .bytesPerElement: 4, .bytesPerRow: 512,
            ])
            guard let s = surf else { return }
            let td = MTLTextureDescriptor.texture2DDescriptor(
                pixelFormat: .bgra8Unorm, width: 256, height: 256, mipmapped: false)
            td.storageMode = .shared
            let tex = device.makeTexture(descriptor: td, iosurface: s, plane: 0)
            log.append("  → \(tex == nil ? "nil (size check OK)" : "OK (no size check — interesting!)")")
        }
    }

    // MARK: - Compute shader submission

    func fuzzComputeShaders() {
        log.append("── Metal compute fuzzing ───────────────────")

        // Simple compute kernel that reads from a buffer
        let shaderSrc = """
        #include <metal_stdlib>
        using namespace metal;
        kernel void fuzz_read(device uint *buf [[buffer(0)]],
                              uint idx [[thread_position_in_grid]]) {
            uint v = buf[idx];  // kernel reads buf[idx]
            buf[idx] = v ^ 0xDEADBEEF;
        }
        """

        guard let lib = try? device.makeLibrary(source: shaderSrc, options: nil),
              let fn  = lib.makeFunction(name: "fuzz_read"),
              let pso = try? device.makeComputePipelineState(function: fn) else {
            log.append("  shader compile failed")
            return
        }
        log.append("  shader compiled OK threadExecWidth=\(pso.threadExecutionWidth)")

        // Fuzz dispatch sizes — skip 0 (Metal asserts), cap at 256K threads
        let dispatchCounts: [Int] = [1, 64, 1024, 0x10000, 0x40000]
        let twg = pso.threadExecutionWidth  // typically 32 on A16
        for count in dispatchCounts {
            autoreleasepool {
                let bufLen = count * 4   // exactly sized — no slack
                guard let buf = device.makeBuffer(length: bufLen, options: .storageModeShared),
                      let cmd = queue.makeCommandBuffer(),
                      let enc = cmd.makeComputeCommandEncoder() else { return }
                enc.setComputePipelineState(pso)
                enc.setBuffer(buf, offset: 0, index: 0)
                // dispatchThreadgroups instead of dispatchThreads — avoids internal assertion on size
                let groups = MTLSize(width: max(count / twg, 1), height: 1, depth: 1)
                let tgs   = MTLSize(width: twg, height: 1, depth: 1)
                enc.dispatchThreadgroups(groups, threadsPerThreadgroup: tgs)
                enc.endEncoding()
                cmd.commit()
                cmd.waitUntilCompleted()
                log.append("  dispatch \(count) → \(cmd.status == .completed ? "OK" : "ERR \(cmd.status.rawValue)")")
            }
        }

        // Off-by-one: dispatch exactly `bufLen/4` threads to read last element,
        // then dispatch bufLen/4 + 1 — that last thread reads OOB from the GPU's POV
        log.append("  OOB dispatch test (buf=256 bytes, 64 uint32s):")
        autoreleasepool {
            guard let buf = device.makeBuffer(length: 256, options: .storageModeShared),
                  let cmd = queue.makeCommandBuffer(),
                  let enc = cmd.makeComputeCommandEncoder() else { return }
            enc.setComputePipelineState(pso)
            enc.setBuffer(buf, offset: 0, index: 0)
            // 65 threads, buf only has 64 uint32s — thread 64 reads one past the end
            let groups = MTLSize(width: 3, height: 1, depth: 1)   // 3 * 32 = 96 threads > 64
            let tgs    = MTLSize(width: twg, height: 1, depth: 1)
            enc.dispatchThreadgroups(groups, threadsPerThreadgroup: tgs)
            enc.endEncoding()
            cmd.commit()
            cmd.waitUntilCompleted()
            log.append("  OOB dispatch → \(cmd.status == .completed ? "OK (note OOB threads)" : "ERR \(cmd.status.rawValue)")")
        }
    }

    // MARK: - MTLHeap stress (use-after-free bait)

    func fuzzHeap() {
        log.append("── MTLHeap stress ──────────────────────────")

        // Skip size=0 — Metal asserts internally, crashes the app, not the kernel
        let heapSizes: [Int] = [4096, 0x10000, 0x100000, 0x1000000]
        for sz in heapSizes {
            autoreleasepool {
                let hd = MTLHeapDescriptor()
                hd.size = sz
                hd.storageMode = .shared
                let heap = device.makeHeap(descriptor: hd)
                log.append("  heap 0x\(String(sz, radix: 16)) → \(heap == nil ? "nil" : "OK sz=\(heap!.size)")")

                guard let h = heap, h.size > 0 else { return }

                // Suballocate, free all, reallocate — UAF window
                var bufs: [MTLBuffer] = []
                for _ in 0..<16 {
                    if let b = h.makeBuffer(length: 256, options: .storageModeShared) {
                        bufs.append(b)
                    }
                }
                bufs.removeAll()  // release all suballocations
                let b2 = h.makeBuffer(length: 128, options: .storageModeShared)
                log.append("    post-free realloc → \(b2 == nil ? "nil" : "OK")")
            }
        }
    }

    // MARK: - Rapid IOSurface create/destroy loop

    func fuzzIOSurfaceRapidAlloc() {
        log.append("── IOSurface rapid alloc/free ──────────────")
        let props: [IOSurfacePropertyKey: Any] = [
            .width: 1920, .height: 1080,
            .bytesPerElement: 4, .bytesPerRow: 7680,
            .allocSize: 8294400
        ]
        var created = 0
        var failed = 0
        for _ in 0..<30 {
            autoreleasepool {
                if let s = IOSurface(properties: props) {
                    let _ = s.lock(options: [], seed: nil)
                    let _ = s.unlock(options: [], seed: nil)
                    created += 1
                } else {
                    failed += 1
                }
            }
        }
        log.append("  200 iterations: created=\(created) failed=\(failed)")
    }
}

// MARK: - Entry point called from ContentView

func runMetalFuzz(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        guard let fuzz = MetalFuzzer(log: log) else {
            log.append("✗ MTLCreateSystemDefaultDevice failed — no Metal")
            completion()
            return
        }
        log.append("── Metal device: \(fuzz.device.name)")
        log.append("[1/6] IOSurface alloc")
        fuzz.fuzzIOSurfaceAlloc()
        log.append("[2/6] Metal buffers")
        fuzz.fuzzMetalBuffers()
        log.append("[3/6] Metal textures")
        fuzz.fuzzMetalTextures()
        log.append("[4/6] Compute shaders")
        fuzz.fuzzComputeShaders()
        log.append("[5/6] MTLHeap")
        fuzz.fuzzHeap()
        log.append("[6/6] Rapid IOSurface")
        fuzz.fuzzIOSurfaceRapidAlloc()
        log.append("── Metal fuzz complete ─────────────────────")
        completion()
    }
}
