# SBX Performance Tool (Standalone 2D Android App)

This repository now contains a standalone Android app wrapper for your `DiagnosticManager` service.

## What was extracted

- Your original diagnostic backend (`DiagnosticManager.java`) is copied into:
  - `app/src/main/java/alvr/client/DiagnosticManager.java`
- A 2D Android UI (`MainActivity`) was added to start/stop it.
- A foreground service (`DiagnosticForegroundService`) runs diagnostics in the background so Android does not kill it easily.

## HTC customized library support

This standalone project includes stub classes under:

- `app/src/main/java/com/htc/customizedlib/`

These stubs let the app compile outside the VR app codebase. Endpoints that depend on HTC proprietary APIs will return stub errors until you replace/link the real HTC library.

## How to enable real HTC endpoints

1. Remove or exclude the stub package `app/src/main/java/com/htc/customizedlib/`.
2. Add the real HTC customized SDK AAR/JAR to the `app` module.
3. Add any required permissions/vendor manifest entries from the VR app.
4. Build on the supported headset/device image that provides those APIs.

## Run behavior

- Start the app.
- Tap `Start Background Server`.
- The foreground service notification appears.
- Access the HTTP API on port `9124` from the same network.

## Notes

- The copied `DiagnosticManager` was patched so stop/start works repeatedly in this standalone wrapper (the HTTP client executor is recreated after shutdown).
- This repo does not include the Gradle wrapper (`gradlew`). Open it in Android Studio and let it generate/import the Gradle files, or add a wrapper from your environment.
