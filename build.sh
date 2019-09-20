cargo build --release
cargo lipo --release
cargo build --release --target aarch64-linux-android
cargo build --release --target armv7-linux-androideabi
cargo build --release --target i686-linux-android
cargo build --release --target x86_64-unknown-linux-gnu
env CROSS_COMPILE=x86_64-linux-musl cargo build --release --target x86_64-unknown-linux-musl