// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NonUIStorage",
    platforms: [.macOS(.v13)],
    dependencies: [.package(path: "../.build/LightTouchMac/Packages/FirmwareKit")],
    targets: [
        .executableTarget(
            name: "RootBuilder",
            dependencies: [.product(name: "FirmwareKit", package: "FirmwareKit")]
        )
    ]
)
