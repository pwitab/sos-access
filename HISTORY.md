# Changelog


The format is based on `Keep a Changelog: https://keepachangelog.com/en/1.0.0/`,
and this project adheres to `Semantic Versioning: https://semver.org/spec/v2.0.0.html`

### Unreleased

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security


## 0.0.7 (2020-03-06)

### Fixed

* Fixed #11. Error in docstring.
* Fixed #10. additional_info on AlarmRequest as dict did not convert to string.
* Fixed #12. Encoding error when sending to some alarm receives.

## 0.0.6 (2020-02-06)

### Fixed

* Upgraded marshmallow to 3.4 and fixed version in installation. Fixes: #6

### Changed

* No exception logging in retry decorator since it creates noise in Sentry.

## 0.0.5 (2019-01-07)

First client implementation ready for production use. Previous version was
development versions and had some bugs in it. It still doesn't support all
features but can be used without things breaking.
Verified against SOS Alarm's alarm system.

