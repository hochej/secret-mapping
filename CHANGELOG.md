# Changelog

All notable changes to this project will be documented in this file.

## [0.1.8] - 2026-02-10

### Changed
- Added explicit AWS host mappings in gondolin export policy:
  - `keyword_host_map["aws"] = ["sts.amazonaws.com", "*.amazonaws.com"]`
  - exact-name mappings for `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

### Fixed
- Removed `private-key -> crt.sh` linkage from gondolin keyword host output to avoid misleading host mapping for generic SSH/private key variables.

## [0.1.7] - 2026-02-10

### Added
- Weekly release automation and generated dataset assets.
