// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "double-ratchet-kit",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "DoubleRatchetKit",
            targets: ["DoubleRatchetKit"],
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.12.3")),
        .package(url: "https://github.com/needletails/needletail-crypto.git", .upToNextMajor(from: "1.1.1")),
        .package(url: "https://github.com/needletails/needletail-algorithms.git", .upToNextMajor(from: "2.0.1")),
        .package(url: "https://github.com/needletails/needletail-logger.git", .upToNextMajor(from: "3.0.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "DoubleRatchetKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NeedleTailCrypto", package: "needletail-crypto"),
                .product(name: "NeedleTailAlgorithms", package: "needletail-algorithms"),
                .product(name: "NeedleTailLogger", package: "needletail-logger"),
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
