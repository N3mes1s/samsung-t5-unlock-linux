# Samsung Portable SSD T5 protocol notes

This document records the interoperability details used by
`samsung-t5-unlock`. It applies only to the original Samsung Portable SSD T5
whose SCSI INQUIRY product string is `Portable SSD T5`.

All transfers use Linux `SG_IO` with 512-byte data buffers and 30-second
timeouts. The commands set ATA PASS-THROUGH `CK_COND`, so a successful command
may return SCSI CHECK CONDITION with an ATA Return Descriptor. The implementation
accepts that response only when ATA status bits `ERR` and `DF` are both clear.

## Challenge-response derivation

Let `challenge` be the 512-byte response from the challenge command and let
`password32` be the password bytes followed by zero bytes to a total length of
32 bytes.

```text
stage1   = SHA256(password32 || challenge[0x30:0x40])
response = SHA256(stage1 || challenge[0x00:0x20])
```

The implementation accepts 1–32 password bytes. Samsung's user interface limits
new passwords to 4–16 characters.

## Command descriptor blocks

Challenge request, 512-byte data-in:

```text
85 08 2e 00 d5 00 01 00 d7 00 4f 00 c2 00 b0 00
```

Unlock response, 512-byte data-out:

```text
85 0a 26 00 d6 00 01 00 c6 00 4f 00 c2 00 b0 00
```

The 32-byte response is placed at payload offset `0x20`.

Relink request, 512-byte zero-filled data-out:

```text
85 0a 26 00 d6 00 01 00 ca 00 4f 00 c2 00 b0 00
```

Disable-security request, 512-byte data-out:

```text
85 0a 26 00 d6 00 01 00 c1 00 4f 00 c2 00 b0 00
```

For this request, payload byte `0x00` is operation `0x06` and the 32-byte
challenge response starts at offset `0x10`. This corresponds to Samsung's
`PSSD_DeleteUserPassword` operation. It changes the enclosure security setting;
it is not a factory-reset or erase command.

## Provenance

The unlock sequence and hash construction were cross-checked against the public
[minmoong/samsung-t5-auto-unlock](https://github.com/minmoong/samsung-t5-auto-unlock)
implementation.

The settings command and delete-password payload were determined through
interoperability analysis of Samsung Portable SSD Software 1.6.7.50. The Linux
implementation was written independently. No Samsung executable or extracted
asset is distributed in this repository.

Samsung documents the supported user-visible behavior—unlocking the T5 and
turning Security Mode off—in the
[Samsung Portable SSD T5 User Manual](https://download.semiconductor.samsung.com/resources/user-manual/Samsung_Portable_SSD_T5_User_Manual_English_1.2.pdf).

Both unlocking and disabling Security Mode were validated on physical T5
hardware. Device serial numbers, passwords, challenges, and user data are
intentionally omitted.
