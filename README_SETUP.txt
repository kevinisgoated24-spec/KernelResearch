===============================================================================
KernelResearch — iOS 26.x Kernel Research App
bad_query sandbox escape + IOKit AGX fuzzer for A16 Bionic (iPhone 15)
===============================================================================

FILES
─────
  bad_query.h / bad_query.c          — containermanagerd path traversal escape
  iokit_fuzz.h / iokit_fuzz.c        — IOKit external method fuzzer
  KernelResearch-Bridging-Header.h   — Swift↔C bridge
  KernelResearch.entitlements        — App Group entitlement for bad_query
  ContentView.swift                  — SwiftUI UI
  KernelResearchApp.swift            — @main entry

===============================================================================
XCODE SETUP (do this on Mac)
===============================================================================

1. CREATE PROJECT
   ─────────────
   • Open Xcode → New Project → iOS → App
   • Product Name: KernelResearch
   • Interface: SwiftUI   Language: Swift
   • Bundle ID: com.yourname.KernelResearch  (use your own)
   • Uncheck "Include Tests"
   • Save somewhere (e.g. ~/Desktop/KernelResearch/)

2. ADD SOURCE FILES
   ────────────────
   Copy all .h, .c, .swift files from this folder into the Xcode project folder.
   Then in Xcode: File → Add Files to "KernelResearch" → select all files.
   Make sure "Copy items if needed" is checked.
   Delete the default ContentView.swift that Xcode auto-generates if it conflicts.

3. ADD IOKit FRAMEWORK
   ────────────────────
   • In the Project Navigator, click the project root (blue icon)
   • Select the "KernelResearch" target → "General" tab
   • Scroll to "Frameworks, Libraries, and Embedded Content"
   • Click "+" → search for IOKit → select IOKit.framework → Add
   Note: IOKit.framework is a private framework on iOS but it IS in the SDK.
         If Xcode doesn't list it, use "Add Other" → browse to:
         /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/
           Developer/SDKs/iPhoneOS.sdk/System/Library/Frameworks/IOKit.framework

4. CONFIGURE BRIDGING HEADER
   ─────────────────────────
   • Project target → Build Settings → search "bridging"
   • "Objective-C Bridging Header" → set to:
     KernelResearch/KernelResearch-Bridging-Header.h

5. ADD ENTITLEMENTS
   ─────────────────
   • Project target → Signing & Capabilities
   • If you have a paid developer account: Add "App Groups" capability
     → Add group: group.cc.forcequit.bad-query
   • If you only have a free account: Skip the App Group (bad_query's system
     path still works without it — just call bad_query(path, false, NULL, false))
   • Alternatively: manually set the entitlements file
     Build Settings → "Code Signing Entitlements" → KernelResearch/KernelResearch.entitlements

6. BUILD SETTINGS
   ───────────────
   • Build Settings → search "Other C Flags" → add: -Wno-deprecated-declarations
   • Build Settings → "Enable Bitcode" → No
   • Deployment Target → iOS 18.0 or later (covers iOS 26.x which reports as 18.x)

7. SIGN & DEPLOY
   ──────────────
   • Signing & Capabilities → Team → select your Apple ID (free works)
   • Connect iPhone 15 via USB, trust if prompted
   • Product → Destination → select your iPhone 15
   • Product → Build (⌘B) first to check for errors
   • Product → Run (⌘R) to install and launch

   Free 7-day cert: The app will expire in 7 days. Re-sign by going to
   Signing & Capabilities, changing the bundle ID slightly, rebuild.

===============================================================================
USAGE
===============================================================================

Once the app launches on device:

  [bad_query Escape]
    → Calls bad_query() for /var/mobile/Library/Caches and other system paths
    → If successful: prints the sandbox extension handle and lists directory
    → Confirms the path traversal is live on iOS 26.5.2

  [Enumerate Services]
    → Calls IOServiceGetMatchingService() for ~12 driver class names
    → Shows which IOUserClient types the sandboxed app can open
    → OPEN_OK means you have a live kernel connection to that driver

  [Fuzz AGX Driver]
    → Fuzzes AGXMetalA16 / IOAcceleratorFamily2 selectors 0..255
    → 16 rounds of random scalar inputs per selector
    → If PORT DIED appears → driver crashed → potential kernel panic found
    → Log interesting kr values for further investigation

  [Fuzz IOSurface]
    → Fuzzes IOSurfaceRoot selectors 0..127
    → IOSurface is a classic kernel bug target (cross-process shared memory)

===============================================================================
WHAT TO LOOK FOR
===============================================================================

In the log output:

  *** AGX CRASH  sel=N — PORT DIED
  → The IOKit service died. This means either:
      a) The app died and reconnected (SIGABRT/SIGSEGV in the driver)
      b) The kernel panic'd and rebooted (you'll see SpringBoard restart)
  → Note the selector N and the input values that triggered it
  → Reproduce with iokit_fuzz_struct_method() on that selector
  → Use OSLog / Console.app on Mac (Window → Devices → View Device Logs)
    to get the panic log or ips file

  OPEN_OK for AGXMetalA16 or IOSurfaceRoot
  → Confirms you have a live kernel connection from sandbox
  → Next step: IOConnectCallMethod with carefully crafted inputs

  bad_query handle >= 0
  → Confirms sandbox escape is live
  → You now have filesystem read access outside your container

===============================================================================
KNOWN LIMITATIONS
===============================================================================

• bad_query gives FILESYSTEM READ access, not write/execute
• IOKit fuzzer starts from a sandboxed app — some services will return
  kIOReturnNotPrivileged (0xe00002c1) without additional entitlements
• SPTM bypass (Stage 4) is a separate, unsolved problem on A16
• The fuzzer is best-effort random — for serious kernel bug hunting,
  combine with a corpus of valid AGX GPU command buffers (from Metal captures)

===============================================================================
NEXT STEPS (kernel r/w research)
===============================================================================

1. Use Metal's MTLCommandBuffer to capture valid AGX command streams
   → Compare valid vs. fuzzed inputs to understand the protocol
   → Mutate valid commands at field boundaries

2. IOSurface cross-process memory:
   → IOSurfaceCreate → IOSurfaceLock → write mapped memory → IOSurfaceUnlock
   → Examine if kernel validates surface metadata vs. mmap'd data

3. Add iokit_fuzz_struct_method() calls for any selector that returned KERN_SUCCESS
   → Try struct sizes from 8 to 4096 bytes to hit allocation boundaries

4. Monitor panic logs in Console.app → Devices → your iPhone → Crash Logs
   → Filter for "Kernel" process type

===============================================================================
