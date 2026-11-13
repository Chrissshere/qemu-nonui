import AppKit

final class Logs: NSObject {
  private enum Channel: String, CaseIterable {
    case session = "Session"
    case console = "Guest Console"
    case qemu = "QEMU"
  }

  private static let tailBytes: UInt64 = 24 * 1024
  private let directory: URL
  private let main = Panel()
  private lazy var detached = Panel()
  private var window: NSWindow?
  private var timer: Timer?
  private var sessionLog: URL?
  private var boot = false

  var view: NSView { main }

  init(directory: URL) {
    self.directory = directory
    super.init()
    let open = NSButton(title: "Open in Window", target: self, action: #selector(openWindow(_:)))
    main.addAction(open)
  }

  func start() {
    refresh()
    guard timer == nil else { return }
    let timer = Timer(timeInterval: 0.75, repeats: true) { [weak self] _ in self?.refresh() }
    self.timer = timer
    RunLoop.main.add(timer, forMode: .common)
  }

  func update(_ file: URL, boot: Bool) {
    sessionLog = file
    self.boot = boot
    main.selectSession()
    if window?.isVisible == true { detached.selectSession() }
    refresh()
  }

  @objc private func openWindow(_ sender: Any?) {
    if window == nil {
      let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 760, height: 490),
        styleMask: [.titled, .closable, .resizable, .miniaturizable],
        backing: .buffered, defer: false
      )
      window.title = "NonUI Logs"
      window.minSize = NSSize(width: 400, height: 240)
      window.isReleasedWhenClosed = false
      let container = NSView()
      window.contentView = container
      detached.translatesAutoresizingMaskIntoConstraints = false
      container.addSubview(detached)
      NSLayoutConstraint.activate([
        detached.topAnchor.constraint(equalTo: container.topAnchor, constant: 14),
        detached.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -14),
        detached.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 14),
        detached.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -14),
      ])
      window.center()
      self.window = window
    }
    detached.select(main.channel)
    window?.makeKeyAndOrderFront(nil)
    refresh()
  }

  private func lastRun() -> URL? {
    let state = directory.appendingPathComponent("session.json")
    guard let data = try? Data(contentsOf: state),
      let record = try? JSONDecoder().decode(Session.self, from: data),
      let run = record.run
    else { return nil }
    return URL(fileURLWithPath: run, isDirectory: true)
  }

  private func refresh() {
    let showMain = main.window?.isVisible == true
    let showDetached = window?.isVisible == true
    guard showMain || showDetached else { return }
    let run = boot || sessionLog == nil ? lastRun() : nil
    if showMain {
      main.update(hasRun: run != nil) { contents(for: $0, run: run) }
    }
    if showDetached {
      detached.update(hasRun: run != nil) { contents(for: $0, run: run) }
    }
  }

  private func contents(for channel: Channel, run: URL?) -> String {
    var files: [URL] = []
    switch channel {
    case .session:
      let fallback = directory.appendingPathComponent(run == nil ? "import.log" : "launch.log")
      files.append(sessionLog ?? fallback)
      if let run {
        files.append(run.appendingPathComponent("boot.log"))
        files.append(run.appendingPathComponent("guest-processes.log"))
      }
    case .console:
      if let run { files.append(run.appendingPathComponent("pram-console-text.txt")) }
    case .qemu:
      if let run { files.append(run.appendingPathComponent("console.log")) }
    }
    let content = files.compactMap(tail).filter { !$0.isEmpty }.joined(separator: "\n\n")
    if !content.isEmpty { return content }
    return channel == .session ? "No logs yet." : "Waiting for output."
  }

  private func tail(_ file: URL) -> String? {
    guard let handle = try? FileHandle(forReadingFrom: file) else { return nil }
    defer { try? handle.close() }
    do {
      let end = try handle.seekToEnd()
      let start = end > Self.tailBytes ? end - Self.tailBytes : 0
      try handle.seek(toOffset: start)
      guard let data = try handle.read(upToCount: Int(Self.tailBytes)) else { return nil }
      var contents = String(decoding: data, as: UTF8.self)
        .replacingOccurrences(of: "\r\n", with: "\n")
        .replacingOccurrences(of: "\r", with: "\n")
      if start > 0, let nextLine = contents.firstIndex(of: "\n") {
        contents = "…\n" + contents[contents.index(after: nextLine)...]
      }
      return contents.trimmingCharacters(in: .newlines)
    } catch {
      return nil
    }
  }

  private struct Session: Decodable {
    let run: String?
  }

  private final class Panel: NSStackView {
    private let bar = NSStackView()
    private let picker = NSPopUpButton()
    private let scroll = NSTextView.scrollableTextView()
    private var lastChannel: Channel?

    var channel: Channel {
      picker.titleOfSelectedItem.flatMap(Channel.init(rawValue:)) ?? .session
    }

    init() {
      super.init(frame: .zero)
      orientation = .vertical
      alignment = .leading
      spacing = 7
      let label = NSTextField(labelWithString: "Logs")
      label.font = .systemFont(ofSize: NSFont.systemFontSize, weight: .medium)
      picker.addItems(withTitles: Channel.allCases.map(\.rawValue))
      picker.setAccessibilityLabel("Log source")
      bar.spacing = 8
      bar.addArrangedSubview(label)
      bar.addArrangedSubview(picker)
      addArrangedSubview(bar)

      scroll.borderType = .bezelBorder
      if let text = scroll.documentView as? NSTextView {
        text.isEditable = false
        text.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        text.textContainerInset = NSSize(width: 9, height: 8)
        text.setAccessibilityLabel("Log output")
      }
      addArrangedSubview(scroll)
      scroll.widthAnchor.constraint(equalTo: widthAnchor).isActive = true
      scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 132).isActive = true
      scroll.setContentHuggingPriority(.defaultLow, for: .vertical)
    }

    required init?(coder: NSCoder) { nil }

    func addAction(_ button: NSButton) {
      bar.addArrangedSubview(button)
    }

    func selectSession() {
      select(.session)
    }

    func select(_ channel: Channel) {
      picker.selectItem(withTitle: channel.rawValue)
    }

    func update(hasRun: Bool, contents: (Channel) -> String) {
      picker.isEnabled = hasRun
      guard let text = scroll.documentView as? NSTextView else { return }
      let channel = hasRun ? channel : .session
      let output = contents(channel)
      guard output != text.string || channel != lastChannel else { return }
      let changedChannel = channel != lastChannel
      if !changedChannel && text.selectedRange().length > 0 { return }
      let position = scroll.contentView.bounds.origin
      let atEnd = scroll.documentVisibleRect.maxY >= text.bounds.maxY - 24
      text.string = output
      lastChannel = channel
      if changedChannel || atEnd {
        text.scrollRangeToVisible(NSRange(location: output.utf16.count, length: 0))
      } else {
        scroll.contentView.scroll(to: position)
        scroll.reflectScrolledClipView(scroll.contentView)
      }
    }
  }
}
