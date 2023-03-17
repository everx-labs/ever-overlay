<p align="center">
  <a href="https://docs.everscale.network/">
    <img src="https://4031793516-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FCmimRVYKp3FChIIdVQ51%2Fuploads%2Fg8DCzYhXFbskTt0odAR4%2FEverscale%20Logo.png?alt=media&token=9484b624-6456-47b4-9757-c0fa43f4caa7" alt="Logo"   height="100">
  </a>
  <a href="https://github.com/venom-blockchain/developer-program">
    <img src="https://raw.githubusercontent.com/venom-blockchain/developer-program/main/vf-dev-program.png" alt="Logo" height="100">
  </a>
</p>


# Overlay

Overlay protocol implementation

## Table of Contents

- [About](#about)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## About

Implementation of Overlay protocol in safe Rust. Overlay protocol runs on top of ADNL UDP, and it is responsible for dividing a single network into additional subnetworks (overlays). Overlays can be both public, to which anyone can connect, and private, where additional credentials is needed for entry, known only to a certain amount of participants.

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

## Tags

`blockchain` `everscale` `rust` `venom-blockchain` `venom-developer-program` `venom-network` 
