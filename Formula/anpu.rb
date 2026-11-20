class Anpu < Formula
  desc "Web security intelligence engine"
  homepage "https://github.com/Marwanmorsy999/anpu"
  version "0.5.9"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.9/anpu_0.5.9_darwin_arm64.tar.gz"
      sha256 "ebc5555b86233daf293ee41e3905a1304f5d886b48691d3d49ee81ce8bb0acd6"
    else
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.9/anpu_0.5.9_darwin_amd64.tar.gz"
      sha256 "7ebebdb66251f43e29a0a4ff36fd13c8aead908780a926897fde8349dd24c6c9"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.9/anpu_0.5.9_linux_arm64.tar.gz"
      sha256 "8555107f3b7e94cd066ebb18421b6f48b87dc479fd32cd360d25c29d25e2a08f"
    else
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.9/anpu_0.5.9_linux_amd64.tar.gz"
      sha256 "e2332fd2c94493a2cf48b0f4234b268eb1998c8644618c86e4a40cebed5af807"
    end
  end

  def install
    bin.install "anpu"
  end

  test do
    system "#{bin}/anpu", "--version"
  end
end