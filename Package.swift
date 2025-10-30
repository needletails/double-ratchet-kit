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
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
        .package(path: "../needletail-crypto"),
//        .package(url: "https://github.com/needletails/needletail-crypto.git", from: "1.1.2"),
        .package(url: "https://github.com/needletails/needletail-algorithms.git", from: "2.0.4"),
        .package(url: "https://github.com/needletails/needletail-logger.git", from: "3.1.1")
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
