# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting or Security Advisory feature
when available. If private reporting is not enabled, open a minimal issue asking
the maintainer for a private contact channel; do not publish exploit details or
sensitive device material in that issue.

Never include any of the following in a report:

- SSD passwords or password-derived responses
- Raw challenge buffers
- Device serial numbers
- Filesystem contents or other user data

Include the tool version, Linux distribution and kernel version, sanitized SCSI
sense information, and exact reproduction steps where safe.

## Security boundaries

This tool requires raw SCSI access. Running it as root gives it the ability to
send commands directly to a storage device. The identity check substantially
reduces accidental targeting, but users should still disconnect unrelated T5
devices and verify the selected `/dev/sgN` node.

The project does not recover, crack, brute-force, log, transmit, or persist
passwords. It can only authenticate with a password already known to the user.

## Supported versions

Security fixes are provided for the latest release on a best-effort basis. There
is no vendor support or warranty.
