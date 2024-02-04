# Changelog

All visible changes will be documented here. This project adheres to Semantic Versioning.

## [0.5.3] - 2024-02-03

### Fixed

- retry timeout argument range in milliseconds
- multi block reader free last block (introduced in 0.5.2)
- server retry increase timeout was not working correctly

## [0.5.2] - 2024-02-01

### Changed

- Use heapless 0.8 version where possible
- Prefer writing to buffer instead of allocating
- Reduce temporary allocations

## [0.5.1] - 2023-12-31

### Added

- Autocomplete scripts

### Changed

- Upgrade polling to latest version

## [0.5.0] - 2023-12-28

### Added

- Ability to receive directory list with server --directly-list option
- Ability to encrypt/decrypt files sent/received using --encryption-key

### Changed

- Including random nonce per encrypted packet (breaking change)

## [0.4.0] - 2023-11-31

### Added

- Ability to sync folders using notify
- Padding for encryption packets (breaking changes for encryption with 0.3.0)

### Changed

- Increased default file limit to 100Mb
- --ignore-rate-limit option removed (its on by default)

### Fixed

- Flow control honour retry_timeout provided 
- Receivers returning incorrect block number on existing blocks
- Trim end of private key

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
