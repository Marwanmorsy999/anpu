class Anpu < Formula
  desc "Web security intelligence engine"
  homepage "https://github.com/Marwanmorsy999/anpu"
  version "0.5.7"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.7/anpu_0.5.7_darwin_arm64.tar.gz"
    else
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.7/anpu_0.5.7_darwin_amd64.tar.gz"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.7/anpu_0.5.7_linux_arm64.tar.gz"
    else
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.7/anpu_0.5.7_linux_amd64.tar.gz"
    end
  end

  def install
    bin.install "anpu"
  end

  test do
    system "#{bin}/anpu", "--version"
  end
end