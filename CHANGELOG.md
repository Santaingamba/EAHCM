# Changelog

All notable changes to the EAHCM C++ Reference Implementation.

## [1.0.0] - 2026-07-17

### Added
- Initial release of the official C++ reference implementation
- Core primitives: L(), F(), R() matching Python bit-for-bit
- Full 4D state machine with step(), drift, and extraction
- HKDF-SHA3-256 key schedule via OpenSSL
- High-level Cipher API with RAII and secure zeroisation
- Binary and JSON state serialization with CRC32 checksums
- Catch2 test suite with reference vector validation
- Examples: keystream generation, state export/import, determinism
- CMake build system with install targets and config packages
- GitHub Actions CI for Windows, Linux, macOS
- Doxygen documentation configuration
