# Changelog

All visible changes will be documented here. This project adheres to Semantic Versioning.

## [0.3.1] - 2023-11-31

### Added

- Ability to sync folders using inotify

### Changed

- Increased default file limit to 100Mb
- Rate limit is on by default (disable it by --ignore-rate-limit)

### Fixed

- Flow control honour retry_timeout provided 
- Receivers returning incorrect block number on existing blocks

## [0.3.0] - 2023-09-11

### Added

- Seek reader available by default
- Command line argument --prefer-seek to use seek reader
- Ability to configure available readers

### Changed

- Separate and improve seek reader
- Writer reduce memory footprint, write sequentially only
- Improve code readability, structure
- Use specific, reader according to window size, preference, availability

### Removed

- Command line argument --max_blocks_in_queue, client will use window-size argument
- Ability to receive packets in a random order

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
