import AppKit
import Foundation

let arguments = CommandLine.arguments
guard arguments.count == 3 else {
  fputs("usage: make-icon SOURCE OUTPUT\n", stderr)
  exit(64)
}

let sourceURL = URL(fileURLWithPath: arguments[1])
let output = URL(fileURLWithPath: arguments[2], isDirectory: true)
guard let loaded = NSImage(contentsOf: sourceURL),
  let source = NSBitmapImageRep(data: loaded.tiffRepresentation ?? Data())
else {
  fputs("Could not read \(sourceURL.path)\n", stderr)
  exit(1)
}

struct Pixel {
  var red: UInt8
  var green: UInt8
  var blue: UInt8
  var alpha: UInt8
}

let width = source.pixelsWide
let height = source.pixelsHigh
var light = [Pixel](repeating: Pixel(red: 0, green: 0, blue: 0, alpha: 0), count: width * height)
var dark = light
var minimumX = width
var minimumY = height
var maximumX = 0
var maximumY = 0

for y in 0..<height {
  for x in 0..<width {
    guard let color = source.colorAt(x: x, y: y)?.usingColorSpace(.sRGB) else { continue }
    let covered = color.alphaComponent
    let white =
      (color.redComponent * covered + (1 - covered)
        + color.greenComponent * covered + (1 - covered)
        + color.blueComponent * covered + (1 - covered)) / 3
    let alpha = max(0, min(1, (1 - white - 0.04) / 0.96))
    let byte = UInt8((alpha * 255).rounded())
    let index = y * width + x
    light[index] = Pixel(red: 0, green: 0, blue: 0, alpha: byte)
    dark[index] = Pixel(red: 255, green: 255, blue: 255, alpha: byte)
    if byte > 8 {
      minimumX = min(minimumX, x)
      minimumY = min(minimumY, y)
      maximumX = max(maximumX, x)
      maximumY = max(maximumY, y)
    }
  }
}

guard maximumX >= minimumX, maximumY >= minimumY else {
  fputs("The icon has no mark.\n", stderr)
  exit(1)
}

func crop(_ pixels: [Pixel]) -> NSImage {
  let cropWidth = maximumX - minimumX + 1
  let cropHeight = maximumY - minimumY + 1
  let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: cropWidth,
    pixelsHigh: cropHeight,
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: cropWidth * 4,
    bitsPerPixel: 32
  )!
  guard let raw = rep.bitmapData else { exit(1) }
  for y in 0..<cropHeight {
    for x in 0..<cropWidth {
      let pixel = pixels[(minimumY + y) * width + minimumX + x]
      let offset = y * rep.bytesPerRow + x * 4
      raw[offset] = pixel.red
      raw[offset + 1] = pixel.green
      raw[offset + 2] = pixel.blue
      raw[offset + 3] = pixel.alpha
    }
  }
  let image = NSImage(size: NSSize(width: cropWidth, height: cropHeight))
  image.addRepresentation(rep)
  return image
}

func bitmap(_ image: NSImage, size: Int) -> NSBitmapImageRep {
  let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: size,
    pixelsHigh: size,
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: size * 4,
    bitsPerPixel: 32
  )!
  NSGraphicsContext.saveGraphicsState()
  let context = NSGraphicsContext(bitmapImageRep: rep)!
  context.imageInterpolation = .high
  NSGraphicsContext.current = context
  NSColor.clear.set()
  NSRect(x: 0, y: 0, width: size, height: size).fill()
  let inset = CGFloat(size) * 0.12
  let box = CGFloat(size) - inset * 2
  let aspect = image.size.width / image.size.height
  let mark =
    aspect >= 1
    ? NSSize(width: box, height: box / aspect)
    : NSSize(width: box * aspect, height: box)
  image.draw(
    in: NSRect(
      x: (CGFloat(size) - mark.width) / 2,
      y: (CGFloat(size) - mark.height) / 2,
      width: mark.width,
      height: mark.height
    ))
  NSGraphicsContext.restoreGraphicsState()
  return rep
}

func write(_ rep: NSBitmapImageRep, to url: URL) throws {
  guard let data = rep.representation(using: .png, properties: [:]) else {
    throw CocoaError(.fileWriteUnknown)
  }
  try data.write(to: url)
}

let slots: [(String, Int)] = [
  ("icon_16x16.png", 16),
  ("icon_16x16@2x.png", 32),
  ("icon_32x32.png", 32),
  ("icon_32x32@2x.png", 64),
  ("icon_128x128.png", 128),
  ("icon_128x128@2x.png", 256),
  ("icon_256x256.png", 256),
  ("icon_256x256@2x.png", 512),
  ("icon_512x512.png", 512),
  ("icon_512x512@2x.png", 1024),
]

let iconSet = output.appendingPathComponent("icon.iconset", isDirectory: true)
try FileManager.default.createDirectory(at: iconSet, withIntermediateDirectories: true)
let lightImage = crop(light)
let darkImage = crop(dark)
try write(bitmap(lightImage, size: 1024), to: output.appendingPathComponent("AppIconLight.png"))
try write(bitmap(darkImage, size: 1024), to: output.appendingPathComponent("AppIconDark.png"))
for (name, size) in slots {
  try write(bitmap(lightImage, size: size), to: iconSet.appendingPathComponent(name))
}
