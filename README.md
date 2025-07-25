# System Application for Edge Device Core

## Overview

The **System Application** is a core component of the [Edge Device Core](https://github.com/aitrios/aitrios-edge-device-core) project. It provides the essential system-level functionality that enables edge devices to securely connect and interact with the [AITRIOS Console](https://www.aitrios.sony-semicon.com/).

### Features

The System Application implements the following critical features for the Edge Device Core:

-   **Cloud Communication:** Manages the device's connection and data exchange with the AITRIOS cloud, including:
    -   **Remote Configuration:** Applying device settings pushed from the AITRIOS Console.
    -   **Status Reporting:** Sending device health, logs, and operational data to the cloud.
    -   **OTA Updates:** Handling over-the-air updates for system software, firmware, and AI models.
    -   **Direct Commands:** Executing remote procedure calls (RPCs) initiated from the Console.
-   **Device Enrollment:** Handles the initial, secure registration of the device with the AITRIOS platform.

### Supported Environments

-   **Raspberry Pi OS** with the [Raspberry Pi Camera Module](https://www.raspberrypi.com/documentation/accessories/ai-camera.html)

## Building the Application

As a submodule of the **Edge Device Core** project, the System Application is not intended to be built as a standalone component. The entire system, including this application, must be built from the top-level `aitrios-edge-device-core` repository.

For complete and detailed build instructions, please consult the [Edge Device Core manual](https://github.com/aitrios/aitrios-edge-device-core).

### Directory Structure

```
.
├── README.md           # This file
├── LICENSE             # Apache 2.0 License
├── CODE_OF_CONDUCT.md  # Community guidelines
├── CONTRIBUTING.md     # Contribution guidelines
├── PrivacyPolicy.md    # Privacy policy
├── SECURITY.md         # Security policy
├── .gitignore          # Git ignore file
├── docs/               # Documentation
├── meson.build         # Meson build configuration
├── src/                # Source code
└── test/               # Unit tests
```

## Contribution

We welcome and encourage contributions to this project! We appreciate bug reports, feature requests, and any other form of community engagement.

-   **Issues and Pull Requests:** Please submit issues and pull requests for any bugs or feature enhancements.
-   **Contribution Guidelines:** For details on how to contribute, please see [CONTRIBUTING.md](CONTRIBUTING.md).
-   **Code of Conduct:** To ensure a welcoming and inclusive community, please review our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

For information on reporting vulnerabilities and our security policy, please refer to the [SECURITY.md](SECURITY.md) file.

## License

This project is licensed under the Apache License 2.0. For more details, please see the [LICENSE](LICENSE) file.
