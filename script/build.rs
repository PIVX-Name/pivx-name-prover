use sp1_build::{build_program_with_args, BuildArgs};

fn main() {
    // The guest ELF must be built with the SAME network features as this host crate.
    //
    // This build script regenerates the ELF on every `cargo build` of `script`, so passing
    // `Default::default()` here would rebuild the guest with no features - i.e. as a
    // MAINNET circuit - silently overwriting whatever `cargo prove build --features
    // testnet` had produced. The runner would then prove the mainnet circuit while the
    // operator believed they were on testnet, and every testnet address in the batch would
    // be rejected as invalid.
    //
    // Forwarding the feature keeps the two halves in lockstep: build the host with
    // `--features testnet` and the guest it embeds is a testnet guest too.
    let mut args = BuildArgs::default();
    if std::env::var_os("CARGO_FEATURE_TESTNET").is_some() {
        args.features = vec!["testnet".to_string()];
    }

    build_program_with_args("../program", args)
}
