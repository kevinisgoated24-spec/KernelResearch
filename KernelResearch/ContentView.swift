import SwiftUI
import UIKit

// MARK: — Log model

class FuzzLog: ObservableObject {
    @Published var lines: [String] = []

    func append(_ s: String) {
        DispatchQueue.main.async {
            self.lines.insert(s, at: 0)
            if self.lines.count > 500 { self.lines.removeLast() }
        }
    }
    func clear() { DispatchQueue.main.async { self.lines.removeAll() } }
}

// Converts a C fixed-size char array (bridged as tuple) to Swift String.
// char detail[256] becomes a 256-element tuple in Swift — String(cString:)
// needs a pointer, not a tuple, so we use withUnsafeBytes.
private func cArrayToString<T>(_ tuple: T) -> String {
    withUnsafeBytes(of: tuple) { rawPtr in
        guard let base = rawPtr.baseAddress else { return "" }
        return String(cString: base.assumingMemoryBound(to: CChar.self))
    }
}

// Retained box for passing Swift closures through C void* context pointer
private class CallbackBox {
    let log: FuzzLog
    init(_ l: FuzzLog) { log = l }
}

// ── ContentView ───────────────────────────────────────────────────────────────

// UIActivityViewController wrapper for SwiftUI
struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}

struct ContentView: View {
    @StateObject private var log = FuzzLog()
    @State private var running = false
    @State private var saveMsg: String? = nil
    @State private var shareURL: URL? = nil
    @State private var showingShare = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        ActionBtn("bad_query\nEscape",  color: .orange) { runBadQuery() }
                        ActionBtn("Enumerate\nServices", color: .blue)  { runEnumerate() }
                        ActionBtn("Fuzz AGX\nDriver",   color: .red)   { runFuzzAGX() }
                        ActionBtn("Fuzz\nIOSurface",    color: .purple) { runFuzzIOSurface() }
                        ActionBtn("Fuzz\nFramebuffer",  color: .teal)  { runFuzzFramebuffer() }
                        ActionBtn("Fuzz\nMetal",        color: .green)   { runFuzzMetal() }
                        ActionBtn("Heap\nOOB",          color: .yellow)  { runHeapOOBTest() }
                        ActionBtn("Heap\nAdjacency",    color: .orange)  { runHeapAdjTest() }
                        ActionBtn("Heap\nSpray",        color: .pink)    { runHeapSprayTest() }
                        ActionBtn("Boundary\nCross",    color: .mint)    { runBoundaryCross() }
                        ActionBtn("Alloc\nConfusion",   color: .indigo)  { runAllocConfusion() }
                        ActionBtn("ArgBuf\nCorrupt",    color: .cyan)    { runArgBufCorrupt() }
                        ActionBtn("Indirect\nDispatch", color: .orange)  { runIndirectDispatch() }
                        ActionBtn("Precision\nCorrupt", color: .purple)  { runPrecisionCorrupt() }
                        ActionBtn("Heap\nUAF",          color: .green)   { runHeapUAF() }
                        ActionBtn("ArgBuf\nConfuse",    color: .red)     { runArgBufConfuse() }
                        ActionBtn("SharedEv\nCorrupt",  color: .mint)    { runSharedEvCorrupt() }
                        ActionBtn("ICB\nCorrupt",       color: .orange)  { runICBCorrupt() }
                        ActionBtn("OOB\nInfo Leak",     color: .yellow)  { runOOBLeak() }
                        ActionBtn("IOSurf\nLeak",       color: .cyan)    { runIOSurfLeak() }
                        ActionBtn("VM\nRegion Scan",    color: .green)   { runVMScan() }
                        ActionBtn("IOSurf\nOOB Esc",    color: .red)     { runIOSurfOOBEsc() }
                        ActionBtn("MISMATCH\nTest",     color: .red)     { triggerMismatch() }
                        ActionBtn("Crash\nLog",         color: .cyan)    { loadCrashLog() }
                        ActionBtn("Save\nLog",          color: .mint)    { saveLog() }
                        ActionBtn("Clear\nLog",         color: .gray)  { log.clear() }
                    }
                    .padding()
                }

                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(log.lines.indices, id: \.self) { i in
                            Text(log.lines[i])
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(lineColor(log.lines[i]))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding(.horizontal, 8)
                }
                .background(Color(white: 0.05))

                if running {
                    ProgressView("Fuzzing…").padding(6).foregroundColor(.yellow)
                }
                if let msg = saveMsg {
                    Text(msg)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.black)
                        .padding(.horizontal, 10).padding(.vertical, 5)
                        .background(Color.mint)
                        .cornerRadius(6)
                        .padding(.bottom, 4)
                        .transition(.opacity)
                }
            }
            .navigationTitle("KernelResearch")
            .navigationBarTitleDisplayMode(.inline)
            .background(Color.black)
        }
        .preferredColorScheme(.dark)
        .sheet(isPresented: $showingShare) {
            if let url = shareURL {
                ShareSheet(items: [url])
            }
        }
    }

    // MARK: — Actions

    private func saveLog() {
        let content = log.lines.reversed().joined(separator: "\n")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("kernel_log_\(Int(Date().timeIntervalSince1970)).txt")
        do {
            try content.write(to: tmp, atomically: true, encoding: .utf8)
            log.append("✓ Written: \(tmp.lastPathComponent) (\(content.utf8.count) bytes) — share sheet opening")
            shareURL = tmp
            showingShare = true
        } catch {
            log.append("✗ Write failed: \(error.localizedDescription)")
            saveMsg = "Write failed"
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) { saveMsg = nil }
        }
    }

    private func runBadQuery() {
        guard !running else { return }
        running = true
        log.append("── bad_query ─────────────────────────────")

        DispatchQueue.global(qos: .userInitiated).async {
            let paths = [
                "/var/mobile/Library/Caches",
                "/var/mobile/Library/Preferences",
                "/var/mobile/Media",
            ]
            for p in paths {
                let handle = bad_query(
                    UnsafeMutablePointer<CChar>(mutating: (p as NSString).utf8String),
                    false, nil, false)
                if handle >= 0 {
                    var isDir: ObjCBool = false
                    let ok = FileManager.default.fileExists(atPath: p, isDirectory: &isDir)
                    self.log.append("✓ \(p) → handle=\(handle) accessible=\(ok)")
                    if ok && isDir.boolValue {
                        if let items = try? FileManager.default.contentsOfDirectory(atPath: p) {
                            for item in items.prefix(6) { self.log.append("    \(item)") }
                        }
                    }
                    bad_query_release(handle)
                } else {
                    // Diagnostic: -1=load fail, -2=query denied (patched?), -3=no token
                    let reason = handle == -2 ? "query denied by cmgrd (patched?)" :
                                 handle == -3 ? "no sandbox token" :
                                 handle == -4 ? "consume_extension failed" : "dylib not found (iOS 26 path?)"
                    self.log.append("✗ \(p) → \(reason) [code=\(handle)]")
                }
            }
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runEnumerate() {
        guard !running else { return }
        running = true
        log.append("── IOKit Service Enumeration ──────────────")

        DispatchQueue.global(qos: .userInitiated).async {
            var outPtr: UnsafeMutablePointer<CChar>? = nil
            let count = iokit_enumerate_services(&outPtr)
            if let ptr = outPtr {
                String(cString: ptr)
                    .components(separatedBy: "\n")
                    .filter { !$0.isEmpty }
                    .forEach { self.log.append($0) }
                free(ptr)
            }
            self.log.append("── Total opened: \(count)")
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runFuzzAGX() {
        guard !running else { return }
        running = true
        log.append("── Fuzzing AGXMetalA16 ────────────────────")

        DispatchQueue.global(qos: .userInitiated).async {
            let box = CallbackBox(self.log)
            let boxPtr = Unmanaged.passRetained(box).toOpaque()

            // C fixed-size char arrays bridge as tuples — use cArrayToString
            let hits = iokit_fuzz_agx({ entryPtr, ctx in
                guard let ep = entryPtr, let ctx = ctx else { return 0 }
                let b = Unmanaged<CallbackBox>.fromOpaque(ctx).takeUnretainedValue()
                let entry = ep.pointee
                let detail = cArrayToString(entry.detail)
                switch entry.result {
                case FUZZ_RESULT_PANIC:
                    b.log.append("*** AGX CRASH  sel=\(entry.selector) — PORT DIED")
                case FUZZ_RESULT_OK:
                    b.log.append("  AGX OK    \(detail)")
                case FUZZ_RESULT_INTERESTING, FUZZ_RESULT_ERROR:
                    b.log.append("  AGX: \(detail)")
                default: break
                }
                return 0
            }, boxPtr)

            Unmanaged<CallbackBox>.fromOpaque(boxPtr).release()
            self.log.append("── AGX done. Interesting hits: \(hits)")
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runFuzzIOSurface() {
        guard !running else { return }
        running = true
        log.append("── Fuzzing IOSurfaceRoot ──────────────────")

        DispatchQueue.global(qos: .userInitiated).async {
            let box = CallbackBox(self.log)
            let boxPtr = Unmanaged.passRetained(box).toOpaque()

            let hits = iokit_fuzz_iosurface({ entryPtr, ctx in
                guard let ep = entryPtr, let ctx = ctx else { return 0 }
                let b = Unmanaged<CallbackBox>.fromOpaque(ctx).takeUnretainedValue()
                let entry = ep.pointee
                let detail = cArrayToString(entry.detail)
                switch entry.result {
                case FUZZ_RESULT_PANIC:
                    b.log.append("*** IOSurface CRASH  sel=\(entry.selector) — PORT DIED")
                case FUZZ_RESULT_OK:
                    b.log.append("  Surface OK  \(detail)")
                case FUZZ_RESULT_INTERESTING:
                    b.log.append("  \(detail)")
                case FUZZ_RESULT_ERROR:
                    b.log.append("  \(detail)")
                default: break
                }
                return 0
            }, boxPtr)

            Unmanaged<CallbackBox>.fromOpaque(boxPtr).release()
            self.log.append("── IOSurface done. Hits: \(hits)")
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func loadCrashLog() {
        let content = SyncLog.read()
        log.append("═══ CRASH LOG ═══════════════════════════")
        content.components(separatedBy: "\n")
            .filter { !$0.isEmpty }
            .reversed()
            .forEach { log.append($0) }
        log.append("═════════════════════════════════════════")
    }

    private func runFuzzMetal() {
        guard !running else { return }
        running = true
        log.append("── Metal + IOSurface Framework Fuzz ────────")
        runMetalFuzz(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runAllocConfusion() {
        guard !running else { return }
        running = true
        log.append("── Allocator Confusion Attack ──────────────")
        runAllocatorConfusion(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runArgBufCorrupt() {
        guard !running else { return }
        running = true
        log.append("── Argument Buffer Corruption ──────────────")
        runArgBufferCorruption(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runIndirectDispatch() {
        guard !running else { return }
        running = true
        log.append("── GPU Indirect Dispatch Corruption ────────")
        runGPUIndirectDispatch(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runICBCorrupt() {
        guard !running else { return }
        running = true
        log.append("── ICB Corrupt ─────────────────────────────")
        runICBCorruptFuzz(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runOOBLeak() {
        guard !running else { return }
        running = true
        log.append("── OOB Info Leak ───────────────────────────")
        runOOBInfoLeak(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runIOSurfLeak() {
        guard !running else { return }
        running = true
        log.append("── IOSurface Backing Store Leak ────────────")
        runIOSurfaceLeak(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runVMScan() {
        guard !running else { return }
        running = true
        log.append("── VM Region Scan ──────────────────────────")
        runVMRegionScan(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runIOSurfOOBEsc() {
        guard !running else { return }
        running = true
        log.append("── IOSurface OOB Escalation ────────────────")
        runIOSurfaceOOBEscalation(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runSharedEvCorrupt() {
        guard !running else { return }
        running = true
        log.append("── SharedEvent Signal Corruption ───────────")
        runSharedEventCorrupt(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runArgBufConfuse() {
        guard !running else { return }
        running = true
        log.append("── ArgBuf Type Confusion ───────────────────")
        runArgBufTypeConfusion(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runHeapUAF() {
        guard !running else { return }
        running = true
        log.append("── Heap Free-List Inject ───────────────────")
        runHeapFreeListInject(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runPrecisionCorrupt() {
        guard !running else { return }
        running = true
        log.append("── Precision Corruption ────────────────────")
        runPrecisionCorruption(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runBoundaryCross() {
        guard !running else { return }
        running = true
        log.append("── Heap Boundary Cross ─────────────────────")
        runHeapBoundaryCross(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runHeapSprayTest() {
        guard !running else { return }
        running = true
        log.append("── Heap Spray Adjacency ────────────────────")
        runHeapSpray(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runHeapAdjTest() {
        guard !running else { return }
        running = true
        log.append("── Heap Adjacency Test ─────────────────────")
        runHeapAdjacency(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runHeapOOBTest() {
        guard !running else { return }
        running = true
        log.append("── MTLHeap OOB Suballoc Probe ──────────────")
        runHeapOOB(log: log) {
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func triggerMismatch() {
        log.append("⚠ MISMATCH TEST — app WILL crash — check Crash Log after reopen")
        runMismatchTest(log: log)
    }

    private func runFuzzFramebuffer() {
        guard !running else { return }
        running = true
        log.append("── Fuzzing IOMobileFramebuffer ────────────")

        DispatchQueue.global(qos: .userInitiated).async {
            let box = CallbackBox(self.log)
            let boxPtr = Unmanaged.passRetained(box).toOpaque()

            let hits = iokit_fuzz_framebuffer({ entryPtr, ctx in
                guard let ep = entryPtr, let ctx = ctx else { return 0 }
                let b = Unmanaged<CallbackBox>.fromOpaque(ctx).takeUnretainedValue()
                let entry = ep.pointee
                let detail = cArrayToString(entry.detail)
                switch entry.result {
                case FUZZ_RESULT_PANIC:
                    b.log.append("*** FRAMEBUFFER CRASH  sel=\(entry.selector) — PORT DIED")
                case FUZZ_RESULT_OK:
                    b.log.append("  FB OK   \(detail)")
                case FUZZ_RESULT_INTERESTING, FUZZ_RESULT_ERROR:
                    b.log.append("  FB: \(detail)")
                default: break
                }
                return 0
            }, boxPtr)

            Unmanaged<CallbackBox>.fromOpaque(boxPtr).release()
            self.log.append("── Framebuffer done. Hits: \(hits)")
            DispatchQueue.main.async { self.running = false }
        }
    }

    // MARK: — Helpers

    private func lineColor(_ line: String) -> Color {
        if line.contains("***") || line.contains("CRASH") { return .red }
        if line.contains("FAIL") || line.contains("✗")   { return .orange }
        if line.contains("✓") || line.contains(" OK ")   { return Color(red: 0.4, green: 1, blue: 0.4) }
        if line.hasPrefix("──")                           { return .yellow }
        return .gray
    }
}

// MARK: — Button component

struct ActionBtn: View {
    let label: String; let color: Color; let action: () -> Void
    init(_ l: String, color: Color, action: @escaping () -> Void) {
        label = l; self.color = color; self.action = action
    }
    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                .multilineTextAlignment(.center)
                .foregroundColor(.white)
                .padding(.vertical, 8).padding(.horizontal, 14)
                .background(color.opacity(0.85))
                .cornerRadius(8)
        }
    }
}
