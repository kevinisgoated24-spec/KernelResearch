import Metal
import IOSurface
import Foundation

func runMetalFuzz(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        guard let device = MTLCreateSystemDefaultDevice(),
              let queue  = device.makeCommandQueue() else {
            log.append("✗ No Metal device"); completion(); return
        }
        log.append("Metal: \(device.name)")

        // ── 1. IOSurface — valid but edge-case props ─────────────────────
        log.append("[1/6] IOSurface alloc")
        let surfCases: [(String, [IOSurfacePropertyKey: Any])] = [
            ("1x1",    [.width:1,   .height:1,   .bytesPerElement:4, .bytesPerRow:4,    .allocSize:4]),
            ("64x64",  [.width:64,  .height:64,  .bytesPerElement:4, .bytesPerRow:256,  .allocSize:16384]),
            ("256x256",[.width:256, .height:256, .bytesPerElement:4, .bytesPerRow:1024, .allocSize:262144]),
            ("13x7",   [.width:13,  .height:7,   .bytesPerElement:4, .bytesPerRow:52,   .allocSize:364]),
        ]
        for (label, props) in surfCases {
            autoreleasepool {
                log.append("  [surf] \(label)")
                guard let s = IOSurface(properties: props) else {
                    log.append("    nil"); return
                }
                log.append("    OK")
                var seed: UInt32 = 0xCAFEBABE
                let lk = s.lock(options: [], seed: &seed)
                let uk = s.unlock(options: [], seed: &seed)
                log.append("    lock=\(lk) unlock=\(uk) seed=0x\(String(seed,radix:16))")
            }
        }

        // ── 2. Buffer page-boundary straddles ────────────────────────────
        log.append("[2/6] Buffer boundaries")
        for sz in [0x3FFF, 0x4000, 0x4001, 0x7FFF, 0x8000, 0xFFFF, 0x100000] {
            autoreleasepool {
                log.append("  [buf] 0x\(String(sz,radix:16))")
                guard let buf = device.makeBuffer(length: sz, options: .storageModeShared) else {
                    log.append("    nil"); return
                }
                let actual = buf.length
                let ptr = buf.contents().assumingMemoryBound(to: UInt8.self)
                ptr[sz - 1] = 0xEE
                if actual > sz { ptr[actual - 1] = 0xFF }
                log.append("    actual=0x\(String(actual,radix:16)) pad=\(actual-sz)")
            }
        }

        // ── 3. IOSurface-backed texture — matched size only ───────────────
        log.append("[3/6] IOSurface-backed texture")
        autoreleasepool {
            log.append("  [tex] matched 128x128")
            guard let surf = IOSurface(properties: [
                .width:128,.height:128,.bytesPerElement:4,.bytesPerRow:512,.allocSize:65536
            ]) else { log.append("    surf nil"); return }
            let td = MTLTextureDescriptor.texture2DDescriptor(
                pixelFormat:.bgra8Unorm, width:128, height:128, mipmapped:false)
            td.storageMode = .shared
            let tex = device.makeTexture(descriptor: td, iosurface: surf, plane: 0)
            log.append("    tex → \(tex == nil ? "nil" : "OK")")
        }
        // MISMATCH: surf 64x64 (16KB), tex 256x256 (262KB) — the key test
        autoreleasepool {
            log.append("  [tex] MISMATCH surf64 tex256")
            guard let surf = IOSurface(properties: [
                .width:64,.height:64,.bytesPerElement:4,.bytesPerRow:256,.allocSize:16384
            ]) else { log.append("    surf nil"); return }
            let td = MTLTextureDescriptor.texture2DDescriptor(
                pixelFormat:.bgra8Unorm, width:256, height:256, mipmapped:false)
            td.storageMode = .shared
            let tex = device.makeTexture(descriptor: td, iosurface: surf, plane: 0)
            log.append("    → \(tex == nil ? "nil (size-checked OK)" : "*** OK no bounds check ***")")
        }

        // ── 4. Blit encoder ──────────────────────────────────────────────
        log.append("[4/6] Blit encoder")
        // Fill + verify pattern
        autoreleasepool {
            log.append("  [blit] fill+verify")
            guard let buf = device.makeBuffer(length: 4096, options: .storageModeShared),
                  let cmd = queue.makeCommandBuffer(),
                  let enc = cmd.makeBlitCommandEncoder() else { return }
            enc.fill(buffer: buf, range: 0..<4096, value: 0xAB)
            enc.endEncoding(); cmd.commit(); cmd.waitUntilCompleted()
            let ptr = buf.contents().assumingMemoryBound(to: UInt8.self)
            log.append("    \(ptr[0]==0xAB && ptr[4095]==0xAB ? "OK" : "MISMATCH")")
        }
        // Non-overlapping copy
        autoreleasepool {
            log.append("  [blit] copy non-overlap")
            guard let src = device.makeBuffer(length: 4096, options: .storageModeShared),
                  let dst = device.makeBuffer(length: 4096, options: .storageModeShared),
                  let cmd = queue.makeCommandBuffer(),
                  let enc = cmd.makeBlitCommandEncoder() else { return }
            src.contents().assumingMemoryBound(to: UInt8.self)[0] = 0x42
            enc.copy(from: src, sourceOffset: 0, to: dst, destinationOffset: 0, size: 4096)
            enc.endEncoding(); cmd.commit(); cmd.waitUntilCompleted()
            let ok = dst.contents().assumingMemoryBound(to: UInt8.self)[0] == 0x42
            log.append("    status=\(cmd.status.rawValue) verify=\(ok)")
        }

        // ── 5. MTLHeap suballoc / UAF stress ────────────────────────────
        log.append("[5/6] MTLHeap")
        for sz in [4096, 0x10000, 0x100000] {
            autoreleasepool {
                log.append("  [heap] 0x\(String(sz,radix:16))")
                let hd = MTLHeapDescriptor(); hd.size = sz; hd.storageMode = .shared
                guard let heap = device.makeHeap(descriptor: hd) else {
                    log.append("    nil"); return
                }
                var bufs: [MTLBuffer] = []
                for _ in 0..<16 {
                    if let b = heap.makeBuffer(length: 256, options: .storageModeShared) {
                        bufs.append(b)
                    }
                }
                let n = bufs.count
                bufs.removeAll()
                let b2 = heap.makeBuffer(length: 128, options: .storageModeShared)
                log.append("    actual=\(heap.size) sub=\(n) realloc=\(b2==nil ? "nil":"OK")")
            }
        }

        // ── 6. Rapid IOSurface create/lock/free ─────────────────────────
        log.append("[6/6] Rapid IOSurface 512x512 x30")
        var ok = 0; var fail = 0
        for _ in 0..<30 {
            autoreleasepool {
                guard let s = IOSurface(properties: [
                    .width:512,.height:512,.bytesPerElement:4,.bytesPerRow:2048,.allocSize:1048576
                ]) else { fail += 1; return }
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
