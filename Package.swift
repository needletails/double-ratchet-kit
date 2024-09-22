// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "double-ratchet-kit",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "DoubleRatchetKit",
            targets: ["DoubleRatchetKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.7.1")),
        .package(url: "https://github.com/apple/swift-testing.git", .upToNextMajor(from: "0.10.0")),
        .package(url: "git@github.com:needle-tail/needletail-crypto.git", .upToNextMajor(from: "1.0.9"))
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "DoubleRatchetKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NeedleTailCrypto", package: "needletail-crypto")
            ]),
        .testTarget(
            name: "DoubleRatchetKitTests",
            dependencies: [
                "DoubleRatchetKit",
                .product(name: "Testing", package: "swift-testing")
            ]
        ),
    ]
)
