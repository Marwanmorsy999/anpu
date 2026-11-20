class Anpu < Formula
  desc "Web security intelligence engine"
  homepage "https://github.com/Marwanmorsy999/anpu"
  version "0.5.10"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.10/anpu_0.5.10_darwin_arm64.tar.gz"
      sha256 "ce3539963d708b3c7ba4c600c7be5495ebb8d48354acf05a51248475c12ecb6f"
    else
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.10/anpu_0.5.10_darwin_amd64.tar.gz"
      sha256 "f5f6fa7ab1ddc355942433ccc65c27cbae44b4f42868dcead502ef6cc61dd5d7"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.10/anpu_0.5.10_linux_arm64.tar.gz"
      sha256 "d93dc906440d2f5dddb14fb126e5fcccf8c6b83e1a7a762c2f7087313a78091f"
    else
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.10/anpu_0.5.10_linux_amd64.tar.gz"
      sha256 "ae48418b84e7ca0b6eeba04e79674076200ecdfa1056f76f65ada71b0922af52"
    end
  end

  def install
    bin.install "anpu"
  end

  test do
    system "#{bin}/anpu", "--version"
  end
end