class Anpu < Formula
  desc "Web security intelligence engine"
  homepage "https://github.com/Marwanmorsy999/anpu"
  version "0.5.8"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.8/anpu_0.5.8_darwin_arm64.tar.gz"
      sha256 "f39db3bab6600381ec5f1debb41610efe03e33b017fc9ef7568cb96ff0649210"
    else
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.8/anpu_0.5.8_darwin_amd64.tar.gz"
      sha256 "c099425e4f694725c135627b3086c9fbbdc53b14117c0b7068ba8024a1918df0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.8/anpu_0.5.8_linux_arm64.tar.gz"
      sha256 "132fc9b193b2fd4588c9b4153c5dfdc49548a7ca9ed7eafd709daa7449a80432"
    else
      url "https://github.com/Marwanmorsy999/anpu/releases/download/v0.5.8/anpu_0.5.8_linux_amd64.tar.gz"
      sha256 "520872781a7a251bb65ca412f8b1a1c40f4a3dfa3838eb96d81fc453ed3edbae"
    end
  end

  def install
    bin.install "anpu"
  end

  test do
    system "#{bin}/anpu", "--version"
  end
end