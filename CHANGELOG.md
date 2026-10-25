# Changelog

## [0.1.4](https://github.com/kushvinth/crowbar/compare/v0.1.3...v0.1.4) (2026-10-25)


### Features

* **sync:** pull datasets from a packaged mirror instead of upstream ([#7](https://github.com/kushvinth/crowbar/issues/7)) ([723decd](https://github.com/kushvinth/crowbar/commit/723decd6ac771604fa9ffd3233375ee8173e8ae5))


### Performance Improvements

* **build:** index package_range.advisory_id before per-advisory deletes ([#11](https://github.com/kushvinth/crowbar/issues/11)) ([24defa0](https://github.com/kushvinth/crowbar/commit/24defa0502c6c15425ff8114c03ab3c364c0d907))
* **build:** index poc.cve_id before counting PoCs per CVE ([#8](https://github.com/kushvinth/crowbar/issues/8)) ([46216ea](https://github.com/kushvinth/crowbar/commit/46216ea5cc317705c56b083198682dce2db9fdc8))

## [0.1.3](https://github.com/kushvinth/crowbar/compare/v0.1.2...v0.1.3) (2026-10-22)


### Bug Fixes

* **sync:** survive flaky NVD downloads and show progress ([#5](https://github.com/kushvinth/crowbar/issues/5)) ([bd58a74](https://github.com/kushvinth/crowbar/commit/bd58a742edee0979cf993bee75e27aff7b06a729))

## [0.1.2](https://github.com/kushvinth/crowbar/compare/v0.1.1...v0.1.2) (2026-10-21)


### Documentation

* **skill:** the PyPI package is crowbar-cli ([0eb1a2d](https://github.com/kushvinth/crowbar/commit/0eb1a2df9e0446f2b91db8da7f052879e901fcbe))

## [0.1.1](https://github.com/kushvinth/crowbar/compare/v0.1.0...v0.1.1) (2026-10-21)


### Bug Fixes

* resolve code scanning alerts ([4c6e0b2](https://github.com/kushvinth/crowbar/commit/4c6e0b29d3e77a890435aa759a0106cf90d68ae6))


### Continuous Integration

* bump the actions group with 5 updates ([#3](https://github.com/kushvinth/crowbar/issues/3)) ([d2834cc](https://github.com/kushvinth/crowbar/commit/d2834cc5716227b1966761f55774bc9cf5cb0a8c))

## [0.1.0](https://github.com/kushvinth/crowbar/compare/v0.1.0...v0.1.0) (2026-10-21)


### Features

* repo made public ([55229a7](https://github.com/kushvinth/crowbar/commit/55229a7226604e5c3bc05bb1c1a08c3728f67711))


### Continuous Integration

* age the index through its meta rows in the upstream e2e ([0e7dc4d](https://github.com/kushvinth/crowbar/commit/0e7dc4dabd149b6c136c136a200dc562980d9b40))
