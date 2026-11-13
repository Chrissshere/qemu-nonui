import CryptoKit
import FirmwareKit
import Foundation

private struct Seed: Decodable {
  let path: String
  let kind: String
  let link: String
  let data: Data
  let uid: UInt32
  let gid: UInt32
  let mode: UInt16
}

private struct BuildError: LocalizedError {
  let errorDescription: String?

  init(_ message: String) {
    errorDescription = message
  }
}

@main
struct RootBuilder {
  private static let rootBytes = 1_342_177_280
  private static let cacheDirectory = "System/Library/Caches/com.apple.dyld/"
  private static let cacheMarker = cacheDirectory + "enable-dylibs-to-override-cache"
  private static let preservedMarker =
    cacheDirectory + "nonui-preserved-enable-dylibs-to-override-cache"

  private static let exclusions = [
    ".DS_Store", ".fseventsd", ".Trashes", ".TemporaryItems",
    ".DocumentRevisions-V100", ".file", ".journal", ".journal_info_block",
    "Developer", "AppleInternal/Restore", "AppleInternal/Diags/Logs",
    "AppleInternal/Diags/Tests", "AppleInternal/Diags/Baseband", "AppleInternal/Diags/ISP",
    "usr/local/standalone", "usr/local/bin", "usr/share/mecabra", "usr/share/tokenizer",
    "usr/share/vim", cacheDirectory + "dyld_shared_cache_armv7s",
    "usr/standalone/firmware/Mav7Mav8-1.00.05.zip",
    "usr/standalone/firmware/Mav7Mav8-1.00.05_DEBUG.zip",
  ]

  private static let bootFiles = [
    "mach.development.s5l8960x": "kernel-development.macho",
    "System/Library/Caches/com.apple.kernelcaches/kernelcache": "kernelcache.im4p",
    "sbin/launchd": "launchd.macho",
    "AppleInternal/Applications/SwitchBoard.app/SwitchBoard": "SwitchBoard.macho",
    cacheDirectory + "dyld_shared_cache_arm64": "dyld_shared_cache_arm64",
  ]

  static func main() async {
    do {
      let arguments = CommandLine.arguments
      guard arguments.count == 4 else {
        throw BuildError("usage: RootBuilder ROOT_DMG VAR_SEED OUTPUT_DIRECTORY")
      }
      try await build(
        source: URL(fileURLWithPath: arguments[1]),
        seedFile: URL(fileURLWithPath: arguments[2]),
        output: URL(fileURLWithPath: arguments[3])
      )
    } catch {
      FileHandle.standardError.write(Data("RootBuilder: \(error.localizedDescription)\n".utf8))
      exit(1)
    }
  }

  private static func build(source input: URL, seedFile: URL, output: URL) async throws {
    let raw = output.appendingPathComponent("source.hfs")
    let image = output.appendingPathComponent("root.hfs")
    guard !FileManager.default.fileExists(atPath: image.path),
      !FileManager.default.fileExists(atPath: raw.path)
    else {
      throw BuildError("The output directory already contains a disk image.")
    }
    defer { try? FileManager.default.removeItem(at: raw) }

    print("Reading the root image")
    try await UDIF.extractRootfs(dmg: input, to: raw, backend: .writer)
    let source = try HFSPlusVolume(raw)
    let records = Dictionary(uniqueKeysWithValues: try source.paths().map { ($0.path, $0.record) })
    let files = try source.listing(hashes: false).filter { item in
      !exclusions.contains { item.path == $0 || item.path.hasPrefix($0 + "/") }
    }

    print("Building the HFSX disk")
    try HFSPlusWriter.makeHFS(
      image, size: Int64(rootBytes), name: "NonUI11A24580o", journaled: true)
    let writer = try HFSPlusWriter(image)
    writer.owner = (uid: 0, gid: 0)
    var hardLinks: [UInt32: String] = [:]
    for item in files {
      guard let record = records[item.path] else {
        throw BuildError("Missing catalog record for \(item.path).")
      }
      switch record.kind {
      case .folder:
        try writer.makeDirectory(item.path, mode: item.mode)
      case .file:
        if let target = item.link {
          try writer.makeSymlink(item.path, to: target)
        } else if record.isHardLink, let first = hardLinks[record.special] {
          try writer.link(item.path, to: first)
        } else {
          try writer.put(source.contents(record), at: item.path, mode: item.mode)
          if record.isHardLink {
            hardLinks[record.special] = item.path
          }
        }
      }
      try writer.setAttributes(item.path, uid: item.uid, gid: item.gid, mode: item.mode)
    }

    let seeds = try JSONDecoder().decode([Seed].self, from: Data(contentsOf: seedFile))
    for seed in seeds {
      let path = "private/" + seed.path
      switch seed.kind {
      case "directory":
        try writer.makeDirectory(path, mode: seed.mode)
      case "symlink":
        if writer.exists(path) {
          try writer.remove(path)
        }
        try writer.makeSymlink(path, to: seed.link)
      case "file":
        try writer.put(seed.data, at: path, mode: seed.mode)
      default:
        throw BuildError("Unsupported seed entry \(seed.path).")
      }
      try writer.setAttributes(path, uid: seed.uid, gid: seed.gid, mode: seed.mode)
    }
    try writer.put(Data("/dev/md0 / hfs rw 0 1\n".utf8), at: "private/etc/fstab", mode: 0o644)
    for item in files {
      let record = records[item.path]!
      let modified = Double(record.dates[1]) - 2_082_844_800
      try writer.setModified(item.path, Date(timeIntervalSince1970: modified))
      try writer.setAttributes(item.path, flags: item.flags & ~UInt32(0x20))
    }
    try writer.setAttributes("", uid: 0, gid: 0, mode: 0o755)
    try writer.rename(cacheMarker, to: preservedMarker)
    try writer.close()

    print("Checking boot files")
    let result = try HFSPlusVolume(image)
    for (path, name) in bootFiles.sorted(by: { $0.key < $1.key }) {
      let expected = try source.contents(source.record(at: path))
      let contents = try result.contents(result.record(at: path))
      guard SHA256.hash(data: expected) == SHA256.hash(data: contents) else {
        throw BuildError("Contents changed for \(path).")
      }
      try contents.write(to: output.appendingPathComponent(name))
    }
    for path in ["bin/sh", "usr/lib/dyld", "var", "etc", "tmp"] {
      guard try source.contents(source.record(at: path)) == result.contents(result.record(at: path))
      else {
        throw BuildError("Contents changed for \(path).")
      }
    }
    let launchd = try result.record(at: "sbin/launchd")
    guard launchd.uid == 0, launchd.gid == 0, launchd.mode & 0o777 == 0o555 else {
      throw BuildError("Unexpected launchd ownership or permissions.")
    }
  }
}
