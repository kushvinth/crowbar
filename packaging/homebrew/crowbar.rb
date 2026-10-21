# Homebrew formula for crowbar. Copy into a tap repo named `homebrew-tap`
# (so `brew install kushvinth/tap/crowbar` works), then fill url + sha256 from
# the published PyPI sdist. The release workflow can bump these automatically
# once the tap repo exists.
class Crowbar < Formula
  include Language::Python::Virtualenv

  desc "Offline vulnerability intelligence for your terminal and your agent"
  homepage "https://github.com/kushvinth/crowbar"
  url "https://files.pythonhosted.org/packages/source/c/crowbar-cli/crowbar_cli-0.1.0.tar.gz"
  sha256 "REPLACE_WITH_SDIST_SHA256"
  license "MIT"

  depends_on "python@3.13"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "crowbar 0.1.0", shell_output("#{bin}/crowbar --version")
  end
end
