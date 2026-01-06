{
  description = "ComLock Crypto - Hybrid Post-Quantum Cryptographic Primitives";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        
        # Use Rust 2024 edition compatible toolchain
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" ];
          targets = [
            "x86_64-unknown-linux-gnu"
            "aarch64-unknown-linux-gnu"
            "aarch64-linux-android"
            "aarch64-apple-ios"
            "aarch64-apple-darwin"
            "x86_64-pc-windows-msvc"
          ];
        };

        # Build inputs for the Rust package
        buildInputs = with pkgs; [
          openssl
          pkg-config
        ];

        # Native build inputs
        nativeBuildInputs = with pkgs; [
          rustToolchain
          pkg-config
        ];

      in {
        # Development shell
        devShells.default = pkgs.mkShell {
          inherit buildInputs nativeBuildInputs;
          
          shellHook = ''
            echo "🔐 ComLock Crypto Development Environment"
            echo "Rust version: $(rustc --version)"
            echo "Cargo version: $(cargo --version)"
          '';

          RUST_BACKTRACE = 1;
          RUST_LOG = "debug";
        };

        # Build the package
        packages = {
          comlock-crypto = pkgs.rustPlatform.buildRustPackage {
            pname = "comlock-crypto";
            version = "0.1.0";
            src = ./.;
            
            cargoLock = {
              lockFile = ./Cargo.lock;
              allowBuiltinFetchGit = true;
            };

            inherit buildInputs nativeBuildInputs;

            # Enforce reproducibility
            postInstall = ''
              # Strip debug symbols for smaller binary
              find $out -type f -name "*.so" -exec strip -s {} \; 2>/dev/null || true
              find $out -type f -executable -exec strip -s {} \; 2>/dev/null || true
              
              # Set deterministic timestamps for reproducibility
              find $out -exec touch -h -d @0 {} + 2>/dev/null || true
            '';

            # Security: Verify no unsafe code
            checkPhase = ''
              cargo clippy -- -D warnings -D unsafe_code
              cargo test --release
            '';

            meta = with pkgs.lib; {
              description = "Hybrid Post-Quantum cryptographic primitives for ComLock";
              homepage = "https://github.com/comlock/comlock-crypto";
              license = with licenses; [ mit asl20 ];
              platforms = platforms.all;
            };
          };

          default = self.packages.${system}.comlock-crypto;
        };

        # Checks
        checks = {
          clippy = pkgs.runCommand "clippy-check" {
            inherit buildInputs nativeBuildInputs;
            src = ./.;
          } ''
            cd $src
            cargo clippy -- -D warnings
            touch $out
          '';

          fmt = pkgs.runCommand "fmt-check" {
            inherit nativeBuildInputs;
            src = ./.;
          } ''
            cd $src
            cargo fmt --check
            touch $out
          '';
        };
      }
    );
}
