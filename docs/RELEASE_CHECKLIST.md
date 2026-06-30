# LibertyGSM release checklist

Use this checklist before publishing a build or GitHub release.

## Required checks

- Run `python scripts/release_check.py`.
- Run `python -m compileall -q gui.py engines divert_engine.py tls_frag.py bypass_proxy.py`.
- On Windows, run `python -c "from engines import create_engine; print(type(create_engine()).__name__)"`.
- Build the Windows executable with `build.bat`.
- Start the built executable as Administrator and confirm the engine starts.
- Confirm `exclude_hosts.txt` is created and editable from the UI.
- Confirm START/STOP restores normal traffic after stopping.
- On macOS/Linux desktop, confirm local proxy mode starts and clearly shows
  `127.0.0.1:10809` as the manual proxy endpoint.

## Platform claims

- Only list Windows as full-system transparent supported until a native engine
  lands for another OS.
- macOS/Linux desktop may be listed as local-proxy preview only.
- macOS must not be marked supported until a signed Network Extension build is tested.
- Android must not be marked supported until a `VpnService` build is tested.
- iOS/iPadOS must not be marked supported until `NEPacketTunnelProvider`,
  entitlements, signing, and real-device tests are complete.

## Artifact hygiene

- Do not commit `build/`, `dist/`, `__pycache__/`, or generated logs.
- Do not commit local `exclude_hosts.txt` changes unless intentionally changing defaults in code.
- Keep `pydivert` Windows-only in dependency metadata.
