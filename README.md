# libsecretstore
Parity secret store client API as C API (FFI)

env CROSS_COMPILE=x86_64-linux-musl cargo build --release --target x86_64-unknown-linux-musl

cargo build --release --target aarch64-linux-android #require ndk 13b

cargo build --release --target armv7-linux-androideabi #require ndk 13b

cargo build --release --target x86_64-unknown-linux-gnu

cargo lipo --release
