class Citrate < Formula
  desc "Citrate AI blockchain platform CLI and node"
  homepage "https://citrate.ai"
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
  if Hardware::CPU.intel?
    if OS.mac?
      url "https://github.com/CitrateNetwork/citrate-chain/releases/download/v#{version}/citrate-v#{version}-macos-x86_64.tar.gz"
      sha256 "PENDING_RELEASE_DIGEST"
    else
      url "https://github.com/CitrateNetwork/citrate-chain/releases/download/v#{version}/citrate-v#{version}-linux-x86_64.tar.gz"
      sha256 "PENDING_RELEASE_DIGEST"
    end
  else
    if OS.mac?
      url "https://github.com/CitrateNetwork/citrate-chain/releases/download/v#{version}/citrate-v#{version}-macos-arm64.tar.gz"
      sha256 "PENDING_RELEASE_DIGEST"
    else
      url "https://github.com/CitrateNetwork/citrate-chain/releases/download/v#{version}/citrate-v#{version}-linux-arm64.tar.gz"
      sha256 "PENDING_RELEASE_DIGEST"
    end
  end

  license "Apache-2.0"

  depends_on "openssl"

  def install
    bin.install "citrate"
    bin.install "citrate-cli"
    bin.install "citrate-wallet"
    bin.install "faucet"

    # Install shell completions
    generate_completions_from_executable(bin/"citrate-cli", "completion")

    # Create config directory
    (etc/"citrate").mkpath

    # Install example configuration
    (etc/"citrate").install "config.toml.example" if File.exist?("config.toml.example")
  end

  def post_install
    puts <<~EOS
      Citrate AI blockchain platform has been installed!

      Quick start:
        1. Initialize a new node:
           citrate init --data-dir ~/.citrate

        2. Start the node:
           citrate start --config ~/.citrate/config.toml

        3. Create a wallet:
           citrate-wallet create

        4. Check node status:
           citrate-cli status

      Documentation: https://docs.citrate.ai
      Community: https://discord.gg/A3Uwe4BvdN
    EOS
  end

  service do
    run [opt_bin/"citrate", "start", "--config", etc/"citrate/config.toml"]
    keep_alive true
    log_path var/"log/citrate.log"
    error_log_path var/"log/citrate.log"
    working_dir var/"lib/citrate"
  end

  test do
    system "#{bin}/citrate", "--version"
    system "#{bin}/citrate-cli", "--help"
    system "#{bin}/citrate-wallet", "--help"
    system "#{bin}/faucet", "--help"
  end
end
