1. Node Topology: Stratified MixnetThe network is composed of three distinct layers of nodes to prevent any single node from knowing both the sender and receiver.Layer 1 (Entry/Gateway): Handles client connections, buffers packets, and enforces RLN spam protection. Knows the User IP but not the destination.Layer 2 (Mix): Shuffles packets. Knows only the previous hop and next hop.Layer 3 (Exit/Mailbox): Stores packets for offline users. Knows the Recipient but not the sender.Topology Rule: Traffic must flow $L1 \rightarrow L2 \rightarrow L3$. Loops can flow $L1 \rightarrow L2 \rightarrow L1$.2. Public Parameters & The TreeThe Merkle Tree: Maintained via a decentralized set of Waku Store nodes.Syncing: Clients do not download the whole tree. They use Light Client Proofs to update their witness (the path to the root) only when they need to send.Anonymity Set: Target set size is $2^{20}$ (1M users). Tree depth: 20.3. CI/CD: The "Nix" Trust PipelineTo ensure no backdoors are inserted by the compiler or build server, we use Nix Flakes.flake.nix snippet:Nix{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay,... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (import rust-overlay) ];
      };
    in {
      # Hermetic build environment
      packages.${system}.comlock-core = pkgs.rustPlatform.buildRustPackage {
        pname = "comlock-core";
        version = "0.1.0";
        src =./.;
        cargoLock = { lockFile =./Cargo.lock; };
        
        # Enforce reproducibility
        postInstall = ''
          strip -R.comment $out/bin/comlock-core
          # Set deterministic timestamps
          find $out -exec touch -h -d @0 {} +
        '';
      };
    }
4. Censorship CircumventionIf the ComLock protocol is identified and blocked by a state firewall (DPI):Pluggable Transports: ComLock packets are wrapped in WebSocket Secure (WSS) to look like HTTPS traffic.Domain Fronting: The initial connection handshake is routed through a major CDN (e.g., Cloudflare/Fastly) so blocking the app requires blocking the entire CDN.Offline Mesh: If the internet is cut, the app switches to P2P Mode using Bluetooth LE and WiFi Direct (via the B.A.T.M.A.N protocol adapted for mobile) to relay packets to a node with uplink connectivity.