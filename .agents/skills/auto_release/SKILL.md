---
name: auto_release
description: Build LibertyGSM into an executable and publish it as a GitHub release.
---

# Auto Release Skill

Use this skill when the user asks to build, compile, package, release, or upload LibertyGSM to GitHub. This skill provides instructions on how to build the executable, package it with PyInstaller, and publish it to the repository's GitHub Releases using the GitHub CLI (`gh`).

## Prerequisites

- **Python**: Installed and in PATH.
- **Git**: Installed and authenticated.
- **GitHub CLI (`gh`)**: Installed and authenticated with push/release permissions for the repository.

## Step-by-Step Instructions

### 1. Version Determination
Before building, decide on a release version tag (e.g., `v1.1.0`).
- You can query the latest tag using:
  ```powershell
  git describe --tags --abbrev=0
  ```
- Increment the version appropriately (patch, minor, or major) or ask the user if unsure.

### 2. Build the Executable
Run the PyInstaller build script to package the app. You can do this by executing `build.bat` or running the command directly:
```powershell
python -m PyInstaller --onefile --noconsole --name=LibertyGSM --uac-admin --collect-all pydivert --collect-all pystray gui.py
```
*Note: Make sure that `dist/LibertyGSM.exe` is successfully generated.*

### 3. Create Git Tag and Push
Commit any pending changes first, then tag the commit and push it to origin:
```powershell
git tag <version_tag>
git push origin <version_tag>
```
*(Example: `git tag v1.0.1` followed by `git push origin v1.0.1`)*

### 4. Publish GitHub Release
Use the GitHub CLI (`gh`) to create a release and upload the compiled binary:
```powershell
gh release create <version_tag> dist\LibertyGSM.exe --title "<version_tag>" --notes "Release description / changelog"
```
*(Example: `gh release create v1.0.1 dist\LibertyGSM.exe --title "v1.0.1" --notes "Bypass whitelist updates and floating notifications"`)*

If the release command succeeds, notify the user with the direct link to the release page.
