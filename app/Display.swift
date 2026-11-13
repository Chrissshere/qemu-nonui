import AppKit
import Foundation

final class Display: NSObject, NSApplicationDelegate {
  private let socket: URL
  private let control: URL
  private let view = GuestPixelsView()
  private let window = NSWindow(
    contentRect: NSRect(x: 0, y: 0, width: 440, height: 760),
    styleMask: [.titled, .closable, .resizable, .miniaturizable],
    backing: .buffered, defer: false
  )
  private var receiver: RawFrameReceiver?
  private var timer: Timer?
  private var controls: [NSButton] = []
  private var keysDown = Set<String>()
  private var presentations: [TimeInterval] = []
  private var sequence: UInt64?
  private var presented = 0

  init(socket: URL, control: URL) {
    self.socket = socket
    self.control = control
    super.init()
    view.controlURL = control
    view.hardwareKey = { [weak self] button, phase in
      self?.button(button, phase: phase)
    }
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    window.title = "11A24580o"
    window.minSize = NSSize(width: 380, height: 450)
    window.center()

    let menu = NSMenu()
    let appItem = NSMenuItem()
    let appMenu = NSMenu()
    appMenu.addItem(
      withTitle: "Close Display", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"
    )
    appItem.submenu = appMenu
    menu.addItem(appItem)
    NSApp.mainMenu = menu

    let content = NSView()
    window.contentView = content
    view.translatesAutoresizingMaskIntoConstraints = false
    view.wantsLayer = true
    view.layer?.backgroundColor = NSColor.black.cgColor
    view.setAccessibilityLabel("Guest display")
    content.addSubview(view)

    let bar = NSStackView()
    bar.orientation = .horizontal
    bar.spacing = 6
    bar.translatesAutoresizingMaskIntoConstraints = false
    let buttons: [(String, Selector)] = [
      ("Home", #selector(home(_:))), ("Power", #selector(power(_:))),
      ("−", #selector(volumeDown(_:))), ("+", #selector(volumeUp(_:))),
    ]
    for (title, action) in buttons {
      let button = NSButton(title: title, target: self, action: action)
      button.bezelStyle = .rounded
      button.isEnabled = false
      bar.addArrangedSubview(button)
      controls.append(button)
    }
    let stop = NSButton(
      title: "Stop", target: NSApp, action: #selector(NSApplication.terminate(_:)))
    stop.bezelStyle = .rounded
    bar.addArrangedSubview(stop)
    content.addSubview(bar)

    NSLayoutConstraint.activate([
      view.topAnchor.constraint(equalTo: content.topAnchor, constant: 8),
      view.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 8),
      view.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -8),
      view.bottomAnchor.constraint(equalTo: bar.topAnchor, constant: -8),
      bar.centerXAnchor.constraint(equalTo: content.centerXAnchor),
      bar.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -8),
    ])
    receiver = RawFrameReceiver(path: socket.path) { [weak self] sequence, pixels in
      self?.present(sequence, pixels: pixels)
    }
    let timer = Timer(timeInterval: 0.5, repeats: true) { [weak self] _ in self?.refresh() }
    self.timer = timer
    RunLoop.main.add(timer, forMode: .common)
    window.makeKeyAndOrderFront(nil)
    window.makeFirstResponder(view)
    NSApp.activate()
  }

  @objc private func home(_ sender: Any?) { button("home", hold: 1.3) }
  @objc private func power(_ sender: Any?) { button("sleep", hold: 0.1) }
  @objc private func volumeDown(_ sender: Any?) { button("volume_down", hold: 0.05) }
  @objc private func volumeUp(_ sender: Any?) { button("volume_up", hold: 0.05) }

  private func button(_ name: String, phase: Int = 1, hold: Double = 0) {
    guard view.inputEnabled || (phase == 6 && keysDown.contains(name)) else { return }
    guard phase != 1 || !keysDown.contains(name) else { return }
    do {
      try send(
        [
          "type": "button", "button": name, "phase": phase, "holdSeconds": hold,
          "hostMonotonicSeconds": ProcessInfo.processInfo.systemUptime,
        ], to: control)
      if phase == 1 && hold == 0 { keysDown.insert(name) }
      if phase == 6 { keysDown.remove(name) }
    } catch {
      NSLog("NonUI input: %@", error.localizedDescription)
    }
  }

  private func present(_ sequence: UInt64, pixels: Data) {
    guard view.showRawFrame(pixels) else { return }
    self.sequence = sequence
    presented += 1
    presentations.append(ProcessInfo.processInfo.systemUptime)
  }

  private func refresh() {
    let now = ProcessInfo.processInfo.systemUptime
    let directory = socket.deletingLastPathComponent()
    let stateURL = directory.appendingPathComponent("live-status.json")
    let state =
      (try? Data(contentsOf: stateURL))
      .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }?["state"]
      as? String
    let recent = presentations.last.map { now - $0 < 8 } ?? false
    let acceptsInput = recent && state != "launching" && state != "stopped"
    view.inputEnabled = acceptsInput
    controls.forEach { $0.isEnabled = acceptsInput }
    presentations.removeAll { now - $0 >= 5 }
    var rate = 0.0
    if let first = presentations.first, let last = presentations.last, last > first {
      rate = Double(presentations.count - 1) / (last - first)
    }
    if state == "launching" {
      window.title = "11A24580o, launching app"
    } else if acceptsInput {
      window.title = String(format: "11A24580o, %.1f fps", rate)
    } else {
      window.title = "11A24580o, waiting"
    }
    if let sequence,
      let data = try? JSONSerialization.data(withJSONObject: [
        "presentedFrames": presented, "lastSequence": sequence, "fps": rate,
      ])
    {
      try? data.write(to: directory.appendingPathComponent("viewer-stats.json"), options: .atomic)
    }
  }

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    true
  }

  func applicationWillTerminate(_ notification: Notification) {
    try? send(["type": "shutdown"], to: control)
  }
}

@main
enum DisplayMain {
  static func main() {
    let arguments = CommandLine.arguments
    guard arguments.count == 3 else { exit(64) }
    let application = NSApplication.shared
    application.setActivationPolicy(.regular)
    let delegate = Display(
      socket: URL(fileURLWithPath: arguments[1]),
      control: URL(fileURLWithPath: arguments[2])
    )
    application.delegate = delegate
    application.run()
  }
}
