import AppKit

enum AppIcon {
  private static var observation: NSKeyValueObservation?

  static func start() {
    apply()
    observation = NSApp.observe(\.effectiveAppearance) { _, _ in
      DispatchQueue.main.async { apply() }
    }
  }

  private static func apply() {
    let dark = NSApp.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
    let name = dark ? "AppIconDark" : "AppIconLight"
    guard let url = Bundle.main.url(forResource: name, withExtension: "png"),
      let image = NSImage(contentsOf: url)
    else { return }
    image.isTemplate = false
    image.size = NSSize(width: 128, height: 128)
    NSApp.applicationIconImage = image
  }
}
