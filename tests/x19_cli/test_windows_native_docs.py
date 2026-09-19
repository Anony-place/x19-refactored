from pathlib import Path


def test_windows_native_install_path_docs_match_installer() -> None:
    doc = Path("website/docs/user-guide/windows-native.md").read_text()
    install = Path("scripts/install.ps1").read_text()

    # The launchers live in the managed binary dir OUTSIDE the git checkout
    # (X19_HOME\bin, next to the managed uv) — NOT the whole venv\Scripts
    # (which would shadow the user's python, #83797) and NOT a dir inside
    # the checkout (which `x19 update`'s autostash swept off disk).
    assert "%LOCALAPPDATA%\\x19\\bin" in doc
    assert (
        "Get-Command x19        # should print "
        "C:\\Users\\<you>\\AppData\\Local\\x19\\bin\\x19.exe"
    ) in doc
    # Installer exposes $X19Home\bin, and must copy the launchers into it.
    assert '$x19Bin = "$X19Home\\bin"' in install
    assert "x19.exe" in install and "x19-acp.exe" in install
    # Guard against regressions to either legacy layout.
    assert '$x19Bin = "$InstallDir\\venv\\Scripts"' not in install
    assert '$x19Bin = "$InstallDir\\bin"' not in install
