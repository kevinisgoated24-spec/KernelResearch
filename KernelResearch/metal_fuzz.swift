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
