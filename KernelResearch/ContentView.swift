import SwiftUI

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

struct ContentView: View {
    @StateObject private var log = FuzzLog()
    @State private var running = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        ActionBtn("bad_query\nEscape",  color: .orange) { runBadQuery() }
                        ActionBtn("Enumerate\nServices", color: .blue)  { runEnumerate() }
                        ActionBtn("Fuzz AGX\nDriver",   color: .red)   { runFuzzAGX() }
                        ActionBtn("Fuzz\nIOSurface",    color: .purple) { runFuzzIOSurface() }
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
            }
            .navigationTitle("KernelResearch")
            .navigationBarTitleDisplayMode(.inline)
            .background(Color.black)
        }
        .preferredColorScheme(.dark)
    }

    // MARK: — Actions

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
                    self.log.append("✗ \(p) → failed")
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
                case FUZZ_RESULT_ERROR:
                    b.log.append("  AGX ERR   \(detail)")
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
                default: break
                }
                return 0
            }, boxPtr)

            Unmanaged<CallbackBox>.fromOpaque(boxPtr).release()
            self.log.append("── IOSurface done. Hits: \(hits)")
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
