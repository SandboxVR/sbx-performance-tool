# SBX Performance Tool (Standalone 2D Android App)

This repository now contains a standalone Android app wrapper for your `DiagnosticManager` service.

## What was extracted

- Original diagnostic backend (`DiagnosticManager.java`) is copied into:
  - `app/src/main/java/alvr/client/DiagnosticManager.java`
- A 2D Android UI (`MainActivity`) was added to start/stop it.
- A foreground service (`DiagnosticForegroundService`) runs diagnostics in the background.

## HTC customized library support

This standalone project includes stub classes under:

- `app/src/main/java/com/htc/customizedlib/`
  
SHA-1 certificate fingerprint
02:3F:E4:80:4C:BC:DA:69:38:A9:5F:0F:89:B6:54:60:A9:B3:C7:7C
