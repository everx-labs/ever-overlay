# Overlay

Overlay protocol implementation

## Table of Contents

- [About](#about)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## About

Implementation of Overlay Protocol (RLDP) in safe Rust. Overlay is a protocol that runs on top of ADNL UDP, which is responsible for dividing a single network into additional subnetworks (overlays). Overlays can be both public, to which anyone can connect, and private, where additional credentials is needed for entry, known only to a certain amount of participants.

## Getting Started

### Prerequisites

Rust complier v1.65+.

### Installing

```
git clone --recurse-submodules https://github.com/tonlabs/ever-overlay.git
cd ever-overlay
cargo build --release
```

## Usage

This project output is the library which is used as a part of Everscale/Venom node. Also it can be used in standalone tools.

## Contributing

Contribution to the project is expected to be done via pull requests submission.

## License

See the [LICENSE](LICENSE) file for details.
