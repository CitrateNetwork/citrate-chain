class Citrate < Formula
  desc "Citrate Network command-line tools and node"
  homepage "https://citrate.ai"
  # Set to the release tag (without the "v") when the first release this formula
  # serves is cut. No v0.4.0 release exists; see homebrew/README.md "Status".
  version "0.4.0"

  # CHAIN-B-E005: URLs point at the canonical CitrateNetwork/citrate-chain
  # repository (the previous `citrate-ai/citrate-v3` org/repo does not exist
  # and an attacker could register it to serve tampered artifacts).
  #
  # The per-platform `sha256` values below are intentionally left as the
  # unresolved marker `PENDING_RELEASE_DIGEST`, which is NOT a valid SHA-256
  # and therefore causes `brew` to FAIL CLOSED (it refuses to install an
  # artifact whose checksum does not match). The release workflow MUST fill
  # each digest with the SHA-256 of the corresponding vendored tarball before
  # this formula is published to a tap. Do NOT replace these with `:no_check`
  # or a hand-copied value that was not computed over the real release
  # artifact — that would install an unverified binary.
  # Asset names follow .github/workflows/release.yml: one tarball per target,
  # citrate-chain-<rust target triple>.tar.gz, holding citrate-chain-<target>/.
  # scripts/tests/test_homebrew_formula.sh checks these names against release.yml.
  if Hardware::CPU.intel?
    if OS.mac?
      url "https://github.com/CitrateNetwork/citrate-chain/releases/download/v#{version}/citrate-chain-x86_64-apple-darwin.tar.gz"
      sha256 "PENDING_RELEASE_DIGEST"
    else
      url "https://github.com/CitrateNetwork/citrate-chain/releases/download/v#{version}/citrate-chain-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PENDING_RELEASE_DIGEST"
    end
  else
    if OS.mac?
      url "https://github.com/CitrateNetwork/citrate-chain/releases/download/v#{version}/citrate-chain-aarch64-apple-darwin.tar.gz"
      sha256 "PENDING_RELEASE_DIGEST"
    else
      url "https://github.com/CitrateNetwork/citrate-chain/releases/download/v#{version}/citrate-chain-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PENDING_RELEASE_DIGEST"
    end
  end

  license "Apache-2.0"

  depends_on "openssl"

  def install
    bin.install "citrate-node"
    bin.install "citrate-cli"
    bin.install "citrate-wallet"
    bin.install "citrate-faucet"

    # Create config directory
    (etc/"citrate").mkpath
  end

  def post_install
    puts <<~EOS
      Citrate command-line tools are installed:
        citrate-cli     chain reads, contract calls and sends (signs locally)
        citrate-wallet  keystore and SALT transfers
        citrate-node    full node
        citrate-faucet  testnet faucet server (operators)

      Quick start against the public network (chain 40204):
        export CITRATE_RPC=https://rpc.citrate.ai
        citrate-cli network status
        citrate-cli account create

      Run a node (joins the public testnet):
        citrate-node --network testnet --data-dir ~/.citrate/node

      Documentation: https://docs.citrate.ai/chain/cli
    EOS
  end

  service do
    run [opt_bin/"citrate-node", "--network", "testnet", "--data-dir", var/"lib/citrate"]
    keep_alive true
    log_path var/"log/citrate.log"
    error_log_path var/"log/citrate.log"
    working_dir var/"lib/citrate"
  end

  test do
    system "#{bin}/citrate-node", "--version"
    system "#{bin}/citrate-cli", "--version"
    system "#{bin}/citrate-wallet", "--help"
    system "#{bin}/citrate-faucet", "--help"
  end
end
