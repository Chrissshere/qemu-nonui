import AppKit
import Foundation

private let build = "11A24580o"
private let rootName = "N51AP_\(build)_rootfs.dmg"
private let varName = "N51AP_\(build)_var.tar"

private enum Input: CaseIterable {
  case root, varSeed, archive

  var button: String {
    switch self {
    case .root: "Choose DMG…"
    case .varSeed: "Choose var tar…"
    case .archive: "Choose Archive…"
    }
  }

  var prompt: String {
    switch self {
    case .root: "Choose " + rootName
    case .varSeed: "Choose " + varName
    case .archive: "Choose a tar or ZIP containing the original firmware files."
    }
  }
}

private final class ImportView: NSView {
  var receive: (([URL]) -> Void)?

  override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
    urls(from: sender).isEmpty ? [] : .copy
  }

  override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
    let files = urls(from: sender)
    guard !files.isEmpty else { return false }
    receive?(files)
    return true
  }

  private func urls(from sender: NSDraggingInfo) -> [URL] {
    sender.draggingPasteboard.readObjects(
      forClasses: [NSURL.self],
      options: [.urlReadingFileURLsOnly: true]
    ) as? [URL] ?? []
  }
}

final class Importer: NSObject, NSApplicationDelegate {
  private let directory: URL
  private let command: URL
  private let profile: URL
  private let window = NSWindow(
    contentRect: NSRect(x: 0, y: 0, width: 618, height: 608),
    styleMask: [.titled, .closable, .resizable, .miniaturizable], backing: .buffered, defer: false
  )
  private let detail = NSTextField(wrappingLabelWithString: "")
  private let progress = NSProgressIndicator()
  private let inputRows = NSStackView()
  private let root = NSTextField(labelWithString: "")
  private let varSeed = NSTextField(labelWithString: "")
  private let archive = NSTextField(labelWithString: "")
  private let prepare = NSButton(title: "Prepare", target: nil, action: nil)
  private let offline = NSButton(title: "Use Local IPSW…", target: nil, action: nil)
  private let ipswLabel = NSTextField(labelWithString: "")
  private let start = NSButton(title: "Boot", target: nil, action: nil)
  private let stop = NSButton(title: "Stop", target: nil, action: nil)
  private let settingsButton = NSButton(title: "Settings…", target: nil, action: nil)
  private let clear = NSButton(title: "Clear All Data and Contents", target: nil, action: nil)
  private let clearMenu = NSMenuItem(
    title: "Clear All Data and Contents", action: #selector(clearData(_:)), keyEquivalent: "")
  private let subtitle = NSTextField(labelWithString: "iPhone 5s, \(build)")
  private lazy var logs = Logs(directory: directory)
  private var experimental = false
  private var settingsWindow: NSWindow?
  private var experimentalToggle: NSButton?

  private struct StoredSettings: Codable {
    var experimental: Bool
  }
  private var selections: [Input: URL] = [:]
  private var ipsw: URL?
  private var operation: Process?
  private var activity: Activity?
  private var pendingQuit = false
  private var output: FileHandle?
  private var logTimer: Timer?

  private enum Activity: Equatable {
    case importing, booting, clearing
  }

  private var removeAfterStop = false

  init(resources: URL, directory: URL) {
    self.directory = directory
    command = resources.appendingPathComponent("nonui")
    profile = directory.appendingPathComponent(build + "/profile.json")
    if let data = try? Data(contentsOf: directory.appendingPathComponent("settings.json")),
      let stored = try? JSONDecoder().decode(StoredSettings.self, from: data)
    {
      experimental = stored.experimental
    }
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    AppIcon.start()
    window.title = "NonUI"
    window.contentMinSize = NSSize(width: 510, height: 502)
    window.center()
    window.isReleasedWhenClosed = false
    let content = ImportView()
    content.receive = { [weak self] in self?.selectFiles($0) }
    content.registerForDraggedTypes([.fileURL])
    window.contentView = content

    let title = NSTextField(labelWithString: "NonUI")
    title.font = .systemFont(ofSize: 23, weight: .semibold)
    subtitle.textColor = .secondaryLabelColor
    let heading = NSStackView(views: [title, subtitle])
    heading.orientation = .vertical
    heading.alignment = .leading
    heading.spacing = 2

    detail.font = .systemFont(ofSize: NSFont.systemFontSize)
    detail.maximumNumberOfLines = 3
    progress.style = .bar
    progress.isIndeterminate = true
    progress.isDisplayedWhenStopped = false

    let actions: [(NSButton, Selector)] = [
      (prepare, #selector(prepareDisk(_:))), (start, #selector(boot(_:))),
      (stop, #selector(stopBoot(_:))),
      (clear, #selector(clearData(_:))),
      (settingsButton, #selector(showSettings(_:))),
      (offline, #selector(selectIPSW(_:))),
    ]
    for (button, action) in actions {
      button.target = self
      button.action = action
      button.bezelStyle = .rounded
    }
    inputRows.orientation = .vertical
    inputRows.alignment = .leading
    inputRows.spacing = 9
    for (kind, label) in [(Input.root, root), (.varSeed, varSeed), (.archive, archive)] {
      let action = NSButton(title: kind.button, target: self, action: #selector(selectInput(_:)))
      action.tag = Input.allCases.firstIndex(of: kind)!
      label.lineBreakMode = .byTruncatingMiddle
      label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
      let row = NSStackView(views: [action, label])
      row.spacing = 10
      inputRows.addArrangedSubview(row)
      row.widthAnchor.constraint(equalTo: inputRows.widthAnchor).isActive = true
    }
    ipswLabel.lineBreakMode = .byTruncatingMiddle
    let ipswRow = NSStackView(views: [offline, ipswLabel])
    ipswRow.spacing = 10
    inputRows.addArrangedSubview(ipswRow)
    ipswRow.widthAnchor.constraint(equalTo: inputRows.widthAnchor).isActive = true
    clear.hasDestructiveAction = true
    let buttons = NSStackView(views: [prepare, start, stop, settingsButton])
    buttons.spacing = 8

    let layout = NSStackView(views: [
      heading, detail, inputRows, progress, buttons, clear, logs.view,
    ])
    layout.orientation = .vertical
    layout.alignment = .leading
    layout.spacing = 13
    layout.translatesAutoresizingMaskIntoConstraints = false
    content.addSubview(layout)
    NSLayoutConstraint.activate([
      layout.topAnchor.constraint(equalTo: content.topAnchor, constant: 23),
      layout.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 23),
      layout.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -23),
      layout.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -20),
      detail.widthAnchor.constraint(equalTo: layout.widthAnchor),
      inputRows.widthAnchor.constraint(equalTo: layout.widthAnchor),
      progress.widthAnchor.constraint(equalTo: layout.widthAnchor),
      logs.view.widthAnchor.constraint(equalTo: layout.widthAnchor),
    ])

    let menu = NSMenu()
    let app = NSMenuItem()
    let commands = NSMenu()
    commands.addItem(
      withTitle: "Settings…", action: #selector(showSettings(_:)), keyEquivalent: ","
    ).target = self
    commands.addItem(.separator())
    commands.addItem(withTitle: "Prepare", action: #selector(prepareDisk(_:)), keyEquivalent: "p")
      .target = self
    commands.addItem(withTitle: "Boot", action: #selector(boot(_:)), keyEquivalent: "b").target =
      self
    clearMenu.target = self
    commands.addItem(clearMenu)
    commands.addItem(.separator())
    commands.addItem(
      withTitle: "Quit NonUI", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    app.submenu = commands
    menu.addItem(app)
    NSApp.mainMenu = menu

    updateControls()
    window.makeKeyAndOrderFront(nil)
    logs.start()
    NSApp.activate()
  }

  func application(_ application: NSApplication, open urls: [URL]) {
    selectFiles(urls)
  }

  func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool
  {
    window.makeKeyAndOrderFront(nil)
    return true
  }

  func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    if operation != nil {
      pendingQuit = true
      if activity == .booting {
        stopBoot(nil)
      }
      return .terminateLater
    }
    return .terminateNow
  }

  @objc private func selectInput(_ sender: NSButton) {
    let input = Input.allCases[sender.tag]
    let prompt: String
    if !experimental {
      prompt = input.prompt
    } else if input == .root {
      prompt = "Choose a root DMG."
    } else if input == .varSeed {
      prompt = "Choose a tar."
    } else {
      prompt = "Choose a tar or ZIP containing a root DMG and a var tar."
    }
    chooseFile(prompt) { [weak self] file in
      guard let self else { return }
      switch input {
      case .root:
        guard file.pathExtension.lowercased() == "dmg" else {
          self.detail.stringValue = "Choose the root DMG."
          return
        }
      case .varSeed:
        guard file.pathExtension.lowercased() == "tar" else {
          self.detail.stringValue = "Choose " + varName + "."
          return
        }
      case .archive:
        self.selectFiles([file])
        return
      }
      self.selections[input] = file
      self.updateControls()
    }
  }

  @objc private func selectIPSW(_ sender: Any?) {
    chooseFile("Choose the iPhone 5s iOS 7.0.1 (11A470a) IPSW.") { [weak self] file in
      guard let self else { return }
      guard file.pathExtension.lowercased() == "ipsw" else {
        self.detail.stringValue = "Choose an IPSW file."
        return
      }
      self.ipsw = file
      self.updateControls()
    }
  }

  private func chooseFile(_ prompt: String, selected: @escaping (URL) -> Void) {
    guard operation == nil else { return }
    let panel = NSOpenPanel()
    panel.message = prompt
    panel.canChooseDirectories = false
    panel.beginSheetModal(for: window) { response in
      if response == .OK, let url = panel.url { selected(url) }
    }
  }

  private func selectFiles(_ files: [URL]) {
    guard operation == nil, !FileManager.default.fileExists(atPath: profile.path) else { return }
    for file in files {
      let name = file.lastPathComponent
      let suffix = file.pathExtension.lowercased()
      if suffix == "ipsw" {
        ipsw = file
      } else if name == varName
        || (suffix == "tar"
          && (experimental
            || (try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize) == 55_808))
        || (experimental && (name.hasSuffix(".tar.gz") || suffix == "tgz"))
      {
        selections[.varSeed] = file
      } else if suffix == "dmg" {
        selections[.root] = file
      } else if suffix == "zip" || suffix == "tar" || name.hasSuffix(".tar.gz") || suffix == "tgz"
        || name.hasSuffix(".tar.xz") || name.hasSuffix(".tar.bz2")
      {
        selections[.archive] = file
      } else {
        detail.stringValue = "Choose the root DMG, var tar, or a firmware archive."
        return
      }
    }
    updateControls()
  }

  @objc private func prepareDisk(_ sender: Any?) {
    guard operation == nil, prepare.isEnabled else { return }
    var files = Input.allCases.compactMap { selections[$0] }
    if let ipsw { files.append(ipsw) }
    var arguments = ["import"]
    if experimental { arguments.append("--experimental") }
    arguments.append(contentsOf: files.map(\.path))
    run(.importing, arguments: arguments)
  }

  @objc private func showSettings(_ sender: Any?) {
    let toggle: NSButton
    if let experimentalToggle {
      toggle = experimentalToggle
    } else {
      let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: 460, height: 210),
        styleMask: [.titled, .closable], backing: .buffered, defer: false)
      window.title = "Settings"
      window.isReleasedWhenClosed = false
      let checkbox = NSButton(
        checkboxWithTitle: "Experimental builds", target: self,
        action: #selector(toggleExperimental(_:)))
      let note = NSTextField(
        wrappingLabelWithString:
          "Off, only the 11A24580o DMG and var tar are accepted. On, prepare tries another DMG or tar. If it is not 11A24580o, it stops and the log says why."
      )
      note.textColor = .secondaryLabelColor
      let stack = NSStackView(views: [checkbox, note])
      stack.orientation = .vertical
      stack.alignment = .leading
      stack.spacing = 12
      stack.translatesAutoresizingMaskIntoConstraints = false
      let content = NSView()
      window.contentView = content
      content.addSubview(stack)
      NSLayoutConstraint.activate([
        stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 20),
        stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 20),
        stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -20),
      ])
      experimentalToggle = checkbox
      settingsWindow = window
      toggle = checkbox
    }
    let action = toggle.action
    toggle.action = nil
    toggle.state = experimental ? .on : .off
    toggle.action = action
    settingsWindow?.center()
    DispatchQueue.main.async { [settingsWindow] in
      settingsWindow?.makeKeyAndOrderFront(nil)
    }
  }

  @objc private func toggleExperimental(_ sender: NSButton) {
    experimental = sender.state == .on
    do {
      try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      let data = try JSONEncoder().encode(StoredSettings(experimental: experimental))
      try data.write(to: directory.appendingPathComponent("settings.json"), options: .atomic)
    } catch {
      detail.stringValue = error.localizedDescription
    }
    updateControls()
  }

  @objc private func boot(_ sender: Any?) {
    guard operation == nil, FileManager.default.fileExists(atPath: profile.path) else { return }
    run(.booting, arguments: ["boot"])
  }

  @objc private func stopBoot(_ sender: Any?) {
    guard activity == .booting, let operation else { return }
    detail.stringValue = "Stopping"
    stop.isEnabled = false
    operation.terminate()
  }

  @objc private func clearData(_ sender: Any?) {
    guard clear.isEnabled else { return }
    let alert = NSAlert()
    alert.messageText = "Remove this VM?"
    alert.informativeText =
      "Are you sure you want to remove this VM? This deletes the prepared disk, runs, and logs. The root DMG and var tar are required to make it bootable again."
    alert.alertStyle = .warning
    alert.addButton(withTitle: "Cancel")
    alert.addButton(withTitle: "Remove VM")
    alert.buttons.last?.hasDestructiveAction = true
    alert.beginSheetModal(for: window) { [weak self] response in
      guard let self, response == .alertSecondButtonReturn else { return }
      if self.activity == .booting {
        self.removeAfterStop = true
        self.stopBoot(nil)
      } else {
        self.run(.clearing, arguments: ["reset"])
      }
    }
  }

  private func run(_ activity: Activity, arguments: [String]) {
    do {
      try FileManager.default.createDirectory(
        at: directory, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      let name =
        activity == .importing ? "import.log" : activity == .clearing ? "reset.log" : "launch.log"
      let log = directory.appendingPathComponent(name)
      try Data().write(to: log, options: .atomic)
      let output = try FileHandle(forWritingTo: log)
      let process = Process()
      process.executableURL = command
      process.arguments = ["--data-dir", directory.path] + arguments
      process.standardOutput = output
      process.standardError = output
      process.terminationHandler = { [weak self] process in
        DispatchQueue.main.async {
          self?.finished(process, activity: activity, log: log)
        }
      }
      try process.run()
      self.output = output
      self.operation = process
      self.activity = activity
      logs.update(log, boot: activity == .booting)
      updateControls()
      detail.stringValue =
        activity == .importing
        ? "Checking import files" : activity == .clearing ? "Removing VM" : "Starting guest"
      let timer = Timer(timeInterval: 0.25, repeats: true) { [weak self] _ in
        self?.showProgress(log)
      }
      logTimer = timer
      RunLoop.main.add(timer, forMode: .common)
    } catch {
      detail.stringValue = error.localizedDescription
      updateControls()
    }
  }

  private func showProgress(_ log: URL) {
    guard let data = try? String(contentsOf: log, encoding: .utf8),
      let last = data.split(whereSeparator: \.isNewline).last
    else { return }
    let message = String(last)
    if message == "SwitchBoard" {
      progress.stopAnimation(nil)
      detail.stringValue = "SwitchBoard"
    } else if message.hasPrefix("READY ") {
      detail.stringValue = "Booting \(build)"
    } else if !message.hasPrefix("Boot log ") && stop.isEnabled {
      detail.stringValue = message
    } else if activity == .importing || activity == .clearing {
      detail.stringValue = message
    }
  }

  private func finished(_ process: Process, activity: Activity, log: URL) {
    logTimer?.invalidate()
    logTimer = nil
    try? output?.close()
    output = nil
    operation = nil
    self.activity = nil
    let continueRemoval = removeAfterStop
    removeAfterStop = false
    if continueRemoval {
      updateControls()
      run(.clearing, arguments: ["reset"])
      return
    }
    updateControls()
    if process.terminationStatus == 0 {
      detail.stringValue =
        activity == .importing
        ? "Disk imported."
        : activity == .clearing
          ? "Removed. Choose the root DMG and var tar to prepare again." : "Stopped."
    } else {
      showProgress(log)
      if let message = (try? String(contentsOf: log, encoding: .utf8))?
        .split(whereSeparator: \.isNewline).last
      {
        detail.stringValue = String(message)
      } else {
        detail.stringValue = "The command ended with status \(process.terminationStatus)."
      }
    }
    if pendingQuit {
      NSApp.reply(toApplicationShouldTerminate: true)
    }
  }

  private var hasStoredVM: Bool {
    [build, "Runs", "Frameworks", "session.json", "import.log", "launch.log"].contains {
      FileManager.default.fileExists(atPath: directory.appendingPathComponent($0).path)
    }
  }

  private func updateControls() {
    let busy = operation != nil
    let imported = FileManager.default.fileExists(atPath: profile.path)
    let hasInputs =
      selections[.archive] != nil || (selections[.root] != nil && selections[.varSeed] != nil)
      || (experimental
        && (selections[.root] != nil || selections[.varSeed] != nil || selections[.archive] != nil))
    subtitle.stringValue =
      experimental ? "iPhone 5s, \(build), experimental" : "iPhone 5s, \(build)"
    for (input, field, placeholder) in [
      (Input.root, root, experimental ? "Any root DMG" : rootName),
      (.varSeed, varSeed, experimental ? "Any tar" : varName),
      (.archive, archive, "Tar or ZIP"),
    ] {
      if let file = selections[input] {
        field.stringValue = file.lastPathComponent
        field.textColor = .labelColor
      } else {
        field.stringValue = placeholder
        field.textColor = .secondaryLabelColor
      }
    }
    ipswLabel.stringValue = ipsw?.lastPathComponent ?? "Optional, iOS 7.0.1 (11A470a)"
    inputRows.isHidden = imported
    for case let row as NSStackView in inputRows.arrangedSubviews {
      for case let button as NSButton in row.arrangedSubviews {
        button.isEnabled = !busy
      }
    }
    prepare.isHidden = imported
    prepare.isEnabled = !busy && !imported && hasInputs
    start.isEnabled = !busy && imported
    stop.isEnabled = activity == .booting
    clear.isHidden = !hasStoredVM
    clear.isEnabled = hasStoredVM && (operation == nil || activity == .booting)
    clearMenu.isEnabled = clear.isEnabled
    start.keyEquivalent = imported ? "\r" : ""
    prepare.keyEquivalent = imported ? "" : "\r"
    if busy {
      progress.startAnimation(nil)
    } else {
      progress.stopAnimation(nil)
      if imported {
        detail.stringValue = "Boot from the imported disk."
      } else if selections.isEmpty {
        detail.stringValue =
          experimental
          ? "Experimental is on. Pick a DMG or a tar."
          : "Pick the root DMG and the var tar, or drop them here."
      } else if hasInputs {
        detail.stringValue =
          experimental
          ? "Prepare will try these files. The log says what failed if they are not 11A24580o."
          : "Click Prepare."
      } else {
        detail.stringValue =
          selections[.root] == nil ? "Choose the root DMG." : "Choose the var tar."
      }
    }
  }
}

@main
enum NonUIMain {
  static func main() {
    guard let resources = Bundle.main.resourceURL else { exit(1) }
    let home = FileManager.default.homeDirectoryForCurrentUser
    let directory =
      ProcessInfo.processInfo.environment["NONUI_DATA_DIR"].map {
        URL(fileURLWithPath: $0, isDirectory: true)
      } ?? home.appendingPathComponent("Library/Application Support/NonUI", isDirectory: true)
    let application = NSApplication.shared
    application.setActivationPolicy(.regular)
    let importer = Importer(resources: resources, directory: directory)
    application.delegate = importer
    application.run()
  }
}
