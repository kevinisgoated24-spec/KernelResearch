import Metal
import IOSurface
import Foundation

func runMetalFuzz(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        guard let device = MTLCreateSystemDefaultDevice(),
              let queue  = device.makeCommandQueue() else {
            log.append("✗ No Metal device")
            completion()
            return
        }
        log.append("Metal: \(device.name)")

        // ── 1. IOSurface edge cases ──────────────────────────────────────
        log.append("[1] IOSurface edge cases")
        let surfCases: [(String, [IOSurfacePropertyKey: Any])] = [
            ("1x1-min",    [.width:1,   .height:1,   .bytesPerElement:4, .bytesPerRow:4,    .allocSize:4]),
            ("64x64",      [.width:64,  .height:64,  .bytesPerElement:4, .bytesPerRow:256,  .allocSize:16384]),
            ("256x256",    [.width:256, .height:256, .bytesPerElement:4, .bytesPerRow:1024, .allocSize:262144]),
            ("1x1-bpr>w",  [.width:1,   .height:1,   .bytesPerElement:4, .bytesPerRow:4096, .allocSize:4096]),  // bpr >> width*bpe
            ("oddW-13x7",  [.width:13,  .height:7,   .bytesPerElement:4, .bytesPerRow:52,   .allocSize:364]),
            ("BGRA-fmt",   [.width:64,  .height:64,  .bytesPerElement:4, .bytesPerRow:256,  .allocSize:16384,
                            .pixelFormat: 0x42475241 as UInt32]),  // 'BGRA'
        ]
        for (label, props) in surfCases {
            autoreleasepool {
                let s = IOSurface(properties: props)
                log.append("  surf \(label) → \(s == nil ? "nil" : "OK")")
                if let s = s {
                    var seed: UInt32 = 0xAABBCCDD
                    let lk = s.lock(options: [], seed: &seed)
                    let uk = s.unlock(options: [], seed: &seed)
                    if lk != 0 || uk != 0 { log.append("    lock=\(lk) unlock=\(uk) non-zero!") }
                }
            }
        }

        // ── 2. Buffer page-boundary straddle ────────────────────────────
        log.append("[2] Buffer page boundaries")
        let pageSizes = [0x3FFF, 0x4000, 0x4001, 0x7FFF, 0x8000, 0x8001, 0xFFFF, 0x100000]
        for sz in pageSizes {
            autoreleasepool {
                guard let buf = device.makeBuffer(length: sz, options: .storageModeShared) else {
                    log.append("  buf 0x\(String(sz,radix:16)) → nil")
                    return
                }
                let actual = buf.length
                // Write pattern at exact end of REQUESTED size (may be inside padding)
                let ptr = buf.contents().assumingMemoryBound(to: UInt8.self)
                ptr[sz - 1] = 0xEE
                ptr[actual - 1] = 0xFF
                log.append("  buf req=0x\(String(sz,radix:16)) actual=0x\(String(actual,radix:16)) pad=\(actual-sz)")
            }
        }

        // ── 3. IOSurface-backed Metal texture (size mismatch test) ───────
        log.append("[3] IOSurface-backed texture")
        // Matched: surf 128x128, tex 128x128 — baseline
        autoreleasepool {
            guard let surf = IOSurface(properties: [.width:128,.height:128,.bytesPerElement:4,.bytesPerRow:512,.allocSize:65536]) else {
                log.append("  surf alloc failed"); return
            }
            let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat:.bgra8Unorm, width:128, height:128, mipmapped:false)
            td.storageMode = .shared
            let tex = device.makeTexture(descriptor: td, iosurface: surf, plane: 0)
            log.append("  matched 128x128 → \(tex == nil ? "nil" : "OK")")
        }
        // MISMATCHED: surf 64x64 (16KB), tex claims 256x256 (262KB) — size check test
        autoreleasepool {
            guard let surf = IOSurface(properties: [.width:64,.height:64,.bytesPerElement:4,.bytesPerRow:256,.allocSize:16384]) else {
                log.append("  surf alloc failed"); return
            }
            let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat:.bgra8Unorm, width:256, height:256, mipmapped:false)
            td.storageMode = .shared
            let tex = device.makeTexture(descriptor: td, iosurface: surf, plane: 0)
            // If OK → Metal didn't bounds-check → GPU can read 16x past the surface end
            log.append("  MISMATCH surf64 tex256 → \(tex == nil ? "nil (size-checked)" : "*** OK — no bounds check ***")")
        }

        // ── 4. Blit encoder operations ───────────────────────────────────
        log.append("[4] Blit encoder")
        // Fill + verify
        autoreleasepool {
            guard let buf = device.makeBuffer(length: 4096, options: .storageModeShared),
                  let cmd = queue.makeCommandBuffer(),
                  let enc = cmd.makeBlitCommandEncoder() else { return }
            enc.fill(buffer: buf, range: 0..<4096, value: 0xAB)
            enc.endEncoding(); cmd.commit(); cmd.waitUntilCompleted()
            let ptr = buf.contents().assumingMemoryBound(to: UInt8.self)
            let ok = ptr[0] == 0xAB && ptr[4095] == 0xAB
            log.append("  fill→verify \(ok ? "OK" : "MISMATCH")")
        }
        // Self-overlapping copy (undefined behavior — might corrupt or crash GPU)
        autoreleasepool {
            guard let buf = device.makeBuffer(length: 8192, options: .storageModeShared),
                  let cmd = queue.makeCommandBuffer(),
                  let enc = cmd.makeBlitCommandEncoder() else { return }
            enc.copy(from: buf, sourceOffset: 0, to: buf, destinationOffset: 64, size: 4096)
            enc.endEncoding(); cmd.commit(); cmd.waitUntilCompleted()
            log.append("  self-overlap-copy status=\(cmd.status.rawValue)")
        }
        // Zero-size copy
        autoreleasepool {
            guard let buf = device.makeBuffer(length: 4096, options: .storageModeShared),
                  let cmd = queue.makeCommandBuffer(),
                  let enc = cmd.makeBlitCommandEncoder() else { return }
            // copy size=0 — Metal may reject or silently accept
            enc.copy(from: buf, sourceOffset: 0, to: buf, destinationOffset: 0, size: 1) // min 1
            enc.endEncoding(); cmd.commit(); cmd.waitUntilCompleted()
            log.append("  min-copy(1 byte) status=\(cmd.status.rawValue)")
        }

        // ── 5. MTLHeap suballoc / UAF window ────────────────────────────
        log.append("[5] MTLHeap")
        for sz in [4096, 0x10000, 0x100000] {
            autoreleasepool {
                let hd = MTLHeapDescriptor(); hd.size = sz; hd.storageMode = .shared
                guard let heap = device.makeHeap(descriptor: hd) else {
                    log.append("  heap 0x\(String(sz,radix:16)) → nil"); return
                }
                log.append("  heap 0x\(String(sz,radix:16)) actual=\(heap.size)")
                var bufs: [MTLBuffer] = []
                for _ in 0..<16 {
                    if let b = heap.makeBuffer(length: 256, options: .storageModeShared) { bufs.append(b) }
                }
                let count = bufs.count
                bufs.removeAll()  // release all — UAF window
                let b2 = heap.makeBuffer(length: 128, options: .storageModeShared)
                log.append("    sub=\(count) post-free-realloc=\(b2 == nil ? "nil" : "OK")")
            }
        }

        // ── 6. Rapid IOSurface alloc / lock / unlock stress ─────────────
        log.append("[6] Rapid IOSurface 512x512 x30")
        var ok = 0; var fail = 0
        for _ in 0..<30 {
            autoreleasepool {
                let props: [IOSurfacePropertyKey: Any] = [
                    .width:512, .height:512, .bytesPerElement:4, .bytesPerRow:2048, .allocSize:1048576
                ]
                guard let s = IOSurface(properties: props) else { fail += 1; return }
                var seed: UInt32 = 0
                let _ = s.lock(options: [], seed: &seed)
                let _ = s.unlock(options: [], seed: &seed)
                ok += 1
            }
        }
        log.append("  created=\(ok) failed=\(fail)")

        log.append("── Metal fuzz complete ─────────────────────")
        completion()
    }
}
