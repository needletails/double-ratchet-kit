// swift-tools-version: 6.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "double-ratchet-kit",
    platforms: [
        .iOS("26.0"),
        .macOS("26.0"),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "DoubleRatchetKit",
            targets: ["DoubleRatchetKit"],
        ),
    ],
    dependencies: [
        .package(url: "git@github.com:needletails/needletail-crypto.git", branch: "migrate/away-from-needletails-swift-crypto"),
        .package(url: "https://github.com/needletails/needletail-logger.git", from: "3.1.5"),
        .package(url: "https://github.com/needletails/binary-codable.git", from: "1.0.3")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "DoubleRatchetKit",
            dependencies: [
                .product(name: "NeedleTailCrypto", package: "needletail-crypto"),
                .product(name: "NeedleTailLogger", package: "needletail-logger"),
                .product(name: "BinaryCodable", package: "binary-codable")
            ],
        ),
        .testTarget(
            name: "DoubleRatchetKitTests",
            dependencies: [
                "DoubleRatchetKit",
            ],
        ),
    ],
)
