import Metal
import IOSurface
import Foundation

// Minimal probe — find crash floor before adding anything else
func runMetalFuzz(log: FuzzLog, completion: @escaping () -> Void) {
    DispatchQueue.global(qos: .userInitiated).async {

        log.append("[step 1] MTLCreateSystemDefaultDevice")
        let dev = MTLCreateSystemDefaultDevice()
        log.append("[step 1] done: \(dev?.name ?? "NIL — no Metal")")
        guard let device = dev else { completion(); return }

        log.append("[step 2] makeCommandQueue")
        let queue = device.makeCommandQueue()
        log.append("[step 2] done: \(queue == nil ? "nil" : "OK")")
        guard let q = queue else { completion(); return }

        log.append("[step 3] makeBuffer 4096 shared")
        let buf = device.makeBuffer(length: 4096, options: .storageModeShared)
        log.append("[step 3] done: \(buf == nil ? "nil" : "OK len=\(buf!.length)")")

        log.append("[step 4] makeCommandBuffer + commit empty")
        if let cmd = q.makeCommandBuffer() {
            cmd.commit()
            cmd.waitUntilCompleted()
            log.append("[step 4] done status=\(cmd.status.rawValue)")
        } else {
            log.append("[step 4] makeCommandBuffer nil")
        }

        log.append("[step 5] IOSurface create 64x64")
        let surf = IOSurface(properties: [
            .width: 64, .height: 64,
            .bytesPerElement: 4, .bytesPerRow: 256,
            .allocSize: 16384,
        ])
        log.append("[step 5] done: \(surf == nil ? "nil" : "OK")")

        if let s = surf {
            log.append("[step 6] IOSurface lock")
            var seed: UInt32 = 0
            let lr = s.lock(options: [], seed: &seed)
            log.append("[step 6] lock kr=\(lr)")
            let ur = s.unlock(options: [], seed: &seed)
            log.append("[step 6] unlock kr=\(ur)")
        }

        log.append("── probe complete ──────────────────────────")
        completion()
    }
}
