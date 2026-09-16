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

        struct Case { let w: Int; let h: Int; let bpe: Int; let bpr: Int }
        let cases: [Case] = [
            Case(w: 0,          h: 0,       bpe: 0,  bpr: 0),
            Case(w: 1,          h: 1,       bpe: 1,  bpr: 1),
            Case(w: 0xFFFF,     h: 0xFFFF,  bpe: 4,  bpr: 0x3FFFC),   // huge
            Case(w: 0x10000,    h: 1,       bpe: 4,  bpr: 0x40000),   // 256 KB wide
            Case(w: 1,          h: 1,       bpe: 4,  bpr: 0x7FFFFFFF),// bpr overflow
            Case(w: 0x1000,     h: 0x1000,  bpe: 16, bpr: 0x10000),   // 64 MB surface
            Case(w: 1,          h: 1,       bpe: 0x7FFFFFFF, bpr: 0x7FFFFFFF), // int overflow bait
        ]

        for c in cases {
            autoreleasepool {
                var props: [IOSurfacePropertyKey: Any] = [
                    .width:          c.w,
                    .height:         c.h,
                    .bytesPerElement: c.bpe,
                    .bytesPerRow:    c.bpr,
                ]
                if c.w > 0 && c.h > 0 && c.bpe > 0 && c.bpr > 0 {
                    let allocSize = c.h * c.bpr
                    if allocSize > 0 && allocSize < 512 * 1024 * 1024 {
                        props[.allocSize] = allocSize
                    }
                }
                let surf = IOSurface(properties: props)
                log.append("  surf \(c.w)x\(c.h) bpe=\(c.bpe) bpr=0x\(String(c.bpr, radix: 16)) → \(surf == nil ? "nil" : "OK id=\(surf!.id)")")

                if let s = surf {
                    // Lock / unlock to trigger kernel mapping
                    let lockResult = s.lock(options: [], seed: nil)
                    let unlockResult = s.unlock(options: [], seed: nil)
                    if lockResult != 0 || unlockResult != 0 {
                        log.append("    lock=\(lockResult) unlock=\(unlockResult) — non-zero interesting")
                    }
                }
            }
        }
    }

    // MARK: - Metal buffer extreme sizes

    func fuzzMetalBuffers() {
        log.append("── Metal buffer extremes ───────────────────")

        let sizes: [Int] = [
            0, 1, 3, 7,
            0x3FFF, 0x4000, 0x3FFFF, 0x40000,   // page boundary
            0xFFFFF, 0x100000,                   // 1 MB
            0x3FFFFFF,                           // 64 MB
            0x7FFFFFFF,                          // 2 GB — should fail gracefully
        ]
        for sz in sizes {
            autoreleasepool {
                let buf = device.makeBuffer(length: max(sz, 1), options: .storageModeShared)
                if let b = buf {
                    log.append("  buf sz=0x\(String(sz, radix: 16)) OK len=\(b.length)")
                    // Write pattern to first/last bytes to see if length is honoured
                    let ptr = b.contents().assumingMemoryBound(to: UInt8.self)
                    ptr[0] = 0xAA
                    if b.length > 1 { ptr[b.length - 1] = 0xBB }
                } else {
                    log.append("  buf sz=0x\(String(sz, radix: 16)) → nil (refused)")
                }
            }
        }
    }

    // MARK: - Texture extreme dimensions + IOSurface-backed textures

    func fuzzMetalTextures() {
        log.append("── Metal texture extremes ──────────────────")

        struct TexCase { let w: Int; let h: Int; let fmt: MTLPixelFormat }
        let cases: [TexCase] = [
            TexCase(w: 1,      h: 1,      fmt: .rgba8Unorm),
            TexCase(w: 16384,  h: 1,      fmt: .rgba8Unorm),   // max dimension boundary
            TexCase(w: 16385,  h: 1,      fmt: .rgba8Unorm),   // over max — should fail
            TexCase(w: 16384,  h: 16384,  fmt: .rgba8Unorm),   // 1 GB texture
            TexCase(w: 0,      h: 0,      fmt: .rgba8Unorm),   // zero-size
            TexCase(w: 65535,  h: 65535,  fmt: .r8Unorm),      // huge
        ]

        for c in cases {
            autoreleasepool {
                let td = MTLTextureDescriptor.texture2DDescriptor(
                    pixelFormat: c.fmt,
                    width:  max(c.w, 1),
                    height: max(c.h, 1),
                    mipmapped: false)
                td.storageMode = .shared
                let tex = device.makeTexture(descriptor: td)
                log.append("  tex \(c.w)x\(c.h) → \(tex == nil ? "nil" : "OK w=\(tex!.width)")")
            }
        }

        // IOSurface-backed texture — the bridge between Metal and IOSurface allocators
        log.append("  IOSurface-backed tex test:")
        autoreleasepool {
            let surfProps: [IOSurfacePropertyKey: Any] = [
                .width: 256, .height: 256,
                .bytesPerElement: 4, .bytesPerRow: 1024,
                .pixelFormat: 0x42475241,   // ARGB big-endian
            ]
            guard let surf = IOSurface(properties: surfProps) else {
                log.append("  surface alloc failed")
                return
            }
            let td = MTLTextureDescriptor.texture2DDescriptor(
                pixelFormat: .bgra8Unorm, width: 256, height: 256, mipmapped: false)
            td.storageMode = .shared
            let tex = device.makeTexture(descriptor: td, iosurface: surf, plane: 0)
            log.append("  IOSurface-backed tex → \(tex == nil ? "nil" : "OK")")
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

        // Fuzz dispatch sizes — including 0, overflow, huge
        let dispatchCounts: [Int] = [0, 1, 64, 1024, 0x10000, 0x100000]
        for count in dispatchCounts {
            autoreleasepool {
                let bufLen = max(count * 4, 4)
                guard let buf = device.makeBuffer(length: bufLen, options: .storageModeShared),
                      let cmd = queue.makeCommandBuffer(),
                      let enc = cmd.makeComputeCommandEncoder() else { return }
                enc.setComputePipelineState(pso)
                enc.setBuffer(buf, offset: 0, index: 0)
                let tg = MTLSize(width: max(count, 1), height: 1, depth: 1)
                let tgs = MTLSize(width: pso.threadExecutionWidth, height: 1, depth: 1)
                enc.dispatchThreads(tg, threadsPerThreadgroup: tgs)
                enc.endEncoding()
                cmd.commit()
                cmd.waitUntilCompleted()
                let status = cmd.status
                log.append("  dispatch \(count) → \(status == .completed ? "OK" : "ERR \(status.rawValue)")")
            }
        }
    }

    // MARK: - MTLHeap stress (use-after-free bait)

    func fuzzHeap() {
        log.append("── MTLHeap stress ──────────────────────────")

        let heapSizes: [Int] = [0, 4096, 0x100000, 0x4000000]
        for sz in heapSizes {
            autoreleasepool {
                let hd = MTLHeapDescriptor()
                hd.size = sz
                hd.storageMode = .shared
                let heap = device.makeHeap(descriptor: hd)
                log.append("  heap sz=0x\(String(sz, radix: 16)) → \(heap == nil ? "nil" : "OK size=\(heap!.size)")")

                if let h = heap, h.size > 0 {
                    // Suballocate from heap and immediately free — race bait
                    var bufs: [MTLBuffer] = []
                    for _ in 0..<8 {
                        if let b = h.makeBuffer(length: 512, options: .storageModeShared) {
                            bufs.append(b)
                        }
                    }
                    // Release all suballocations, then do another alloc — UAF window
                    bufs.removeAll()
                    let _ = h.makeBuffer(length: 256, options: .storageModeShared)
                }
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
        for _ in 0..<200 {
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
        fuzz.fuzzIOSurfaceAlloc()
        fuzz.fuzzMetalBuffers()
        fuzz.fuzzMetalTextures()
        fuzz.fuzzComputeShaders()
        fuzz.fuzzHeap()
        fuzz.fuzzIOSurfaceRapidAlloc()
        log.append("── Metal fuzz complete ─────────────────────")
        completion()
    }
}
