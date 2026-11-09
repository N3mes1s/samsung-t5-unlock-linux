# samsung-t5-unlock

`samsung-t5-unlock` is a small native Linux utility for managing password
protection on the original Samsung Portable SSD T5. It uses Linux `SG_IO` to
send the enclosure's ATA pass-through commands and has no runtime dependencies
beyond the Linux kernel and libc.

> [!WARNING]
> This software sends undocumented vendor commands to storage hardware. Back up
> important data first. Use it only with an original Samsung Portable SSD T5
> that you own and for which you know the current password.

## Supported hardware

The program requires both of these exact SCSI INQUIRY strings before it sends a
vendor command:

- Vendor: `Samsung`
- Product: `Portable SSD T5`

It is **not** intended for the T5 EVO, T7, T7 Touch, T7 Shield, or other Samsung
drives. The tested T5 enumerated as USB `04e8:61f6` while locked and
`04e8:61f5` while unlocked or with security disabled.

## Features

- Auto-detects a matching `/dev/sgN` device or accepts an explicit device path.
- Verifies the exact device identity before every proprietary operation.
- Unlocks the data volume using the known password.
- Permanently disables password locking without formatting or factory reset.
- Reads passwords only from a hidden `/dev/tty` prompt—never from arguments or
  environment variables.
- Disables core dumps and process dumpability, locks password buffers in RAM
  when permitted, and explicitly wipes sensitive buffers.
- Never mounts, formats, repartitions, or edits the data filesystem.
- Submits an authentication response once; it does not guess or retry passwords.

## Requirements

- Linux with SCSI generic (`SG_IO`) support
- A C11 compiler and standard Linux development headers (`scsi/sg.h`)
- Root access, unless a local device policy grants access to the `/dev/sgN` node

## Build and test

```sh
make
make check
```

Install under `/usr/local/sbin`:

```sh
sudo make install
```

Packaging can override `PREFIX`, `SBINDIR`, and `DESTDIR`.

## Usage

Start with the non-mutating identity probe:

```sh
sudo ./samsung-t5-unlock --probe
```

Verify the read-only challenge command without printing challenge material:

```sh
sudo ./samsung-t5-unlock --challenge-only
```

Unlock the T5 for the current connection:

```sh
sudo ./samsung-t5-unlock
```

The tool requests the password using a hidden terminal prompt, asks the
enclosure to relink, and waits for the full-capacity `/dev/sdX` device. It does
not mount the filesystem.

To permanently turn password security off, first unlock the T5 and unmount its
data partition, then run:

```sh
sudo ./samsung-t5-unlock --disable-security
```

The current password is required again. This invokes Samsung's authenticated
delete-password operation; it does not factory-reset or erase the data volume.
Disconnect and reconnect the T5 afterward to verify that full capacity appears
without another password.

If multiple T5 devices are connected, choose the SCSI generic node explicitly:

```sh
sudo ./samsung-t5-unlock --device /dev/sg0 --probe
```

## Protocol and provenance

See [PROTOCOL.md](PROTOCOL.md) for the command layouts, challenge-response
derivation, and interoperability research notes.

The unlock flow was cross-checked against
[minmoong/samsung-t5-auto-unlock](https://github.com/minmoong/samsung-t5-auto-unlock).
The disable-security transaction was independently implemented from
interoperability analysis of Samsung Portable SSD Software 1.6.7.50. No Samsung
executables, extracted assets, passwords, or device data are included in this
repository.

Samsung's manual documents both password unlocking and turning Security Mode
off: [Samsung Portable SSD T5 User Manual](https://download.semiconductor.samsung.com/resources/user-manual/Samsung_Portable_SSD_T5_User_Manual_English_1.2.pdf).

## Security

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Do not include
passwords, challenge bytes, device serial numbers, or private data in a public
issue.

## License and trademarks

The project is available under the [MIT License](LICENSE).

Samsung and Portable SSD are trademarks of Samsung Electronics Co., Ltd. This
independent project is not affiliated with, endorsed by, or supported by
Samsung.
