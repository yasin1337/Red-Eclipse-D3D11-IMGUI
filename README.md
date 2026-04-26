# Red Eclipse D3D11 Overlay ImGui

This is an ImGui overlay built with D3D11, designed to be easily expandable to other applications.

## Technical Details

### Configuration
- **Process Targeting**: Configured via `TARGET_PROCESS` in `Drawing.h`.
- **Offset Management**: All memory addresses are centralized in `Offsets.h`.
- **Custom Logic**: All rendering and feature implementation is located in `Drawing.cpp`.

### Requirements
- Microsoft Visual Studio 2022 or later.
- DirectX 11 SDK.

### Controls
- **INSERT**: Toggle menu visibility.
- **END**: Terminate the overlay.

## Disclaimer

This project is intended strictly for educational purposes. It demonstrates techniques for DirectX 11 overlay rendering and external process memory visualisation. Tested in offline mode ONLY!
