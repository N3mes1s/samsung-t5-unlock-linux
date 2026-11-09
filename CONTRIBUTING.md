# Contributing

Contributions are welcome, especially reproducible fixes for the original
Samsung Portable SSD T5.

Before submitting a change:

```sh
make clean check
```

For changes to hashing, SCSI result parsing, or payload construction, also run a
sanitized build:

```sh
cc -O1 -g -std=c11 -Wall -Wextra -Wpedantic -Werror \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  samsung-t5-unlock.c -o samsung-t5-unlock-sanitize
ASAN_OPTIONS=detect_leaks=0 ./samsung-t5-unlock-sanitize --self-test
```

Protocol changes should include a deterministic self-test and a clear provenance
note. Hardware test reports must omit passwords, challenges, serial numbers, and
filesystem data.

Do not commit vendor installers, extracted proprietary binaries, USB captures
containing sensitive material, compiled executables, or static-analysis output.

By contributing, you agree that your contribution is licensed under the MIT
License.
