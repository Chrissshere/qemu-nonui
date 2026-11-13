import Accelerate
import AppKit
import CoreVideo
import Darwin
import Foundation
import IOSurface
import System

final class RawFrameReceiver {
  static let width = 640
  static let height = 1136
  static let byteCount = width * height * 4
  private let delivery = DispatchSource.makeUserDataAddSource(queue: .main)
  private let lock = NSLock()
  private var latest: (UInt64, Data)?

  init(path: String, onFrame: @escaping (UInt64, Data) -> Void) {
    delivery.setEventHandler { [weak self] in
      guard let self else { return }
      self.lock.lock()
      let frame = self.latest
      self.latest = nil
      self.lock.unlock()
      if let frame { onFrame(frame.0, frame.1) }
    }
    delivery.activate()
    DispatchQueue(label: "NonUI raw frames", qos: .userInitiated).async { [weak self] in
      self?.receive(path: path)
    }
  }

  private func receive(path: String) {
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let pathBytes = path.utf8CString
    guard pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { return }
    withUnsafeMutableBytes(of: &address.sun_path) { destination in
      pathBytes.withUnsafeBytes { destination.copyMemory(from: $0) }
    }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return }
    defer { close(fd) }
    let result = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
      }
    }
    guard result == 0 else {
      NSLog("NonUI frame stream connect: %s", strerror(errno))
      return
    }
    while let header = readExactly(fd, length: 16),
      header.prefix(4) == Data([0x4e, 0x55, 0x49, 0x46])
    {
      let length = header.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) }
      guard length == Self.byteCount, let pixels = readExactly(fd, length: Self.byteCount) else {
        break
      }
      let sequence = header.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt64.self) }
      lock.lock()
      latest = (sequence, pixels)
      lock.unlock()
      delivery.add(data: 1)
    }
  }

  private func readExactly(_ fd: Int32, length: Int) -> Data? {
    var data = Data(count: length)
    let complete = data.withUnsafeMutableBytes { (buffer: UnsafeMutableRawBufferPointer) -> Bool in
      guard let base = buffer.baseAddress else { return false }
      var offset = 0
      while offset < length {
        let received = recv(fd, base + offset, length - offset, 0)
        if received < 0 && errno == EINTR { continue }
        guard received > 0 else { return false }
        offset += received
      }
      return true
    }
    return complete ? data : nil
  }
}

final class GuestPixelsView: NSView {
  var controlURL: URL?
  var hardwareKey: ((String, Int) -> Void)?
  var inputEnabled = false {
    didSet { if !inputEnabled { pointerDown = false } }
  }
  private var pointerDown = false
  private var pointerOrigin = NSPoint.zero
  private var dragging = false
  private var sequence = 0

  private let frameLayer = CALayer()
  private var surfaces: [IOSurfaceRef] = []
  private var currentSurface: Int?

  private var imageSize: NSSize {
    NSSize(width: RawFrameReceiver.width, height: RawFrameReceiver.height)
  }

  override func layout() {
    super.layout()
    CATransaction.begin()
    CATransaction.setDisableActions(true)
    frameLayer.frame = bounds
    CATransaction.commit()
  }

  func showRawFrame(_ pixels: Data) -> Bool {
    let width = RawFrameReceiver.width
    let height = RawFrameReceiver.height
    let rowBytes = width * 4
    if surfaces.isEmpty {
      let properties: [CFString: Any] = [
        kIOSurfaceWidth: width, kIOSurfaceHeight: height,
        kIOSurfaceBytesPerElement: 4, kIOSurfaceBytesPerRow: rowBytes,
        kIOSurfacePixelFormat: kCVPixelFormatType_32BGRA,
      ]
      let allocated = (0..<3).compactMap { _ in IOSurfaceCreate(properties as CFDictionary) }
      guard allocated.count == 3, let layer else { return false }
      surfaces = allocated
      frameLayer.frame = bounds
      frameLayer.contentsGravity = .resizeAspect
      frameLayer.magnificationFilter = .nearest
      frameLayer.minificationFilter = .nearest
      layer.addSublayer(frameLayer)
    }
    guard
      let index = surfaces.indices.first(where: {
        $0 != currentSurface && !IOSurfaceIsInUse(surfaces[$0])
      })
    else { return false }
    let surface = surfaces[index]
    guard IOSurfaceLock(surface, [], nil) == kIOReturnSuccess else { return false }
    let result = pixels.withUnsafeBytes { buffer -> vImage_Error in
      guard let base = buffer.baseAddress else { return kvImageNullPointerArgument }
      var source = vImage_Buffer(
        data: UnsafeMutableRawPointer(mutating: base),
        height: vImagePixelCount(height), width: vImagePixelCount(width),
        rowBytes: rowBytes)
      var destination = vImage_Buffer(
        data: IOSurfaceGetBaseAddress(surface),
        height: vImagePixelCount(height), width: vImagePixelCount(width),
        rowBytes: IOSurfaceGetBytesPerRow(surface))
      return vImagePermuteChannels_ARGB8888(
        &source, &destination, [2, 1, 0, 3], vImage_Flags(kvImageNoFlags))
    }
    IOSurfaceUnlock(surface, [], nil)
    guard result == kvImageNoError else { return false }
    CATransaction.begin()
    CATransaction.setDisableActions(true)
    frameLayer.contents = surface
    CATransaction.commit()
    currentSurface = index
    return true
  }

  private func sendPointer(_ event: NSEvent, phase: Int) {
    guard inputEnabled, let controlURL else { return }
    let image = imageSize
    let scale = min(bounds.width / image.width, bounds.height / image.height)
    guard scale > 0 else { return }
    let rect = NSRect(
      x: (bounds.width - image.width * scale) / 2,
      y: (bounds.height - image.height * scale) / 2,
      width: image.width * scale, height: image.height * scale)
    var point = convert(event.locationInWindow, from: nil)
    if phase == 1 {
      guard rect.contains(point) else { return }
      pointerDown = true
      pointerOrigin = point
      dragging = false
    }
    guard pointerDown else { return }
    if phase == 2 && !dragging {
      guard hypot(point.x - pointerOrigin.x, point.y - pointerOrigin.y) >= 3 else { return }
      dragging = true
    }
    if phase == 6 && !dragging { point = pointerOrigin }
    if phase == 6 { pointerDown = false }
    sequence += 1
    let record: [String: Any] = [
      "type": "pointer", "sequence": sequence,
      "phase": phase, "fingerID": 1, "fingerCount": 1,
      "x": min(max((point.x - rect.minX) / scale, 0), image.width - 1),
      "y": min(max((rect.maxY - point.y) / scale, 0), image.height - 1),
      "width": image.width, "height": image.height,
      "hostMonotonicSeconds": ProcessInfo.processInfo.systemUptime,
    ]
    do {
      try send(record, to: controlURL)
    } catch {
      NSLog("NonUI input: %@", error.localizedDescription)
    }
  }

  override var acceptsFirstResponder: Bool { true }
  override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
  override func mouseDown(with event: NSEvent) {
    window?.makeFirstResponder(self)
    sendPointer(event, phase: 1)
  }
  override func mouseDragged(with event: NSEvent) { sendPointer(event, phase: 2) }
  override func mouseUp(with event: NSEvent) { sendPointer(event, phase: 6) }
  override func keyDown(with event: NSEvent) {
    if event.keyCode == 53, !event.isARepeat {
      hardwareKey?("home", 1)
    } else {
      super.keyDown(with: event)
    }
  }
  override func keyUp(with event: NSEvent) {
    if event.keyCode == 53 { hardwareKey?("home", 6) } else { super.keyUp(with: event) }
  }

}

func send(_ event: [String: Any], to queue: URL) throws {
  var data = try JSONSerialization.data(withJSONObject: event, options: [.sortedKeys])
  data.append(10)
  let file = try FileDescriptor.open(FilePath(queue.path), .writeOnly, options: .append)
  defer { try? file.close() }
  try file.writeAll(data)
}
