#!/bin/zsh

rustup toolchain install nightly
rustup target add "aarch64-apple-ios" "x86_64-apple-darwin" "aarch64-apple-darwin" "x86_64-apple-ios" "aarch64-apple-ios-sim"
cargo build --release --target-dir target --target "aarch64-apple-ios" --target "x86_64-apple-darwin" --target "aarch64-apple-darwin" --target "x86_64-apple-ios" --target "aarch64-apple-ios-sim"
rustup component add rust-src --toolchain nightly-aarch64-apple-darwin
cargo +nightly build --release --target-dir target -Z build-std --target x86_64-apple-ios-macabi --target aarch64-apple-ios-macabi
lipo -create target/x86_64-apple-darwin/release/libpenumbra_c_bindings.a target/aarch64-apple-darwin/release/libpenumbra_c_bindings.a -output libpenumbra_c_bindings_macos.a
lipo -create target/x86_64-apple-ios-macabi/release/libpenumbra_c_bindings.a target/aarch64-apple-ios-macabi/release/libpenumbra_c_bindings.a -output libpenumbra_c_bindings_maccatalyst.a
xcodebuild -create-xcframework -library ./libpenumbra_c_bindings_macos.a -headers ./include/ -library ./libpenumbra_c_bindings_iossimulator.a -headers ./include/ -library ./libpenumbra_c_bindings_maccatalyst.a -headers ./include/ -library ./target/aarch64-apple-ios/release/libpenumbra_c_bindings.a -headers ./include/ -output penumbra_c_bindings.xcframework

zip -r bundle.zip penumbra_c_bindings.xcframework
