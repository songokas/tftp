# Changelog

All visible changes will be documented here. This project adheres to Semantic Versioning.

## [0.2.0] - 2023-04-22

### Added

- Server load balance connections
- Server use multi threads by default
- Secure server directory so that files do not escape provided directory
- Retry window size from last acknoledged
- Initial flow control

### Changed

- Default retry timeout from seconds to milliseconds
- Default retry timeout from 1000ms to 80ms

## [0.1.0] - 2023-02-15

### Added

- Initial tftp binary and library realese