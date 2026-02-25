# cpp-keccak256

A minimal, header-friendly C++20 implementation of **Keccak-256** — the *original* Keccak hash (0x01 padding), as used by Ethereum.

This is **not** SHA3-256 (FIPS 202), which uses 0x06 padding and produces different digests.

Based on the [Keccak reference](https://keccak.team/files/Keccak-reference-3.0.pdf).

## Build

Requires a C++20 compiler (GCC 10+, Clang 11+).

```sh
make            # builds libkeccak256.a and runs the test binary
make test       # builds and runs tests
make clean
```

## Usage

Copy `keccak256.h` and `keccak256.cc` into your project, or link against `libkeccak256.a`.

### One-shot (simplest)

```cpp
#include "keccak256.h"

auto digest = keccak256("hello", 5);
// digest is std::array<uint8_t, 32>
```

### One-shot with string_view or span

```cpp
auto digest = keccak256(std::string_view("hello"));

std::vector<uint8_t> data = {0x01, 0x02, 0x03};
auto digest = keccak256(std::span<const uint8_t>(data));
```

### Streaming (incremental)

```cpp
Keccak k;                       // defaults to 32-byte output
k.Update("hello ", 6);
k.Update(std::string_view("world"));
auto digest = k.Finalize();     // returns std::array<uint8_t, 32>
```

### Reset and reuse

```cpp
Keccak k;
k.Update("first message", 13);
auto d1 = k.Finalize();

k.Reset();
k.Update("second message", 14);
auto d2 = k.Finalize();
```

## Test vectors

The test suite (`test.cc`) contains 25 tests including:

- Ethereum canonical vectors (empty string, `"abc"`)
- NIST competition strings (56-byte, 112-byte)
- Rate boundary tests (135, 136, 137 bytes)
- Multi-block input (200 bytes)
- Incrementing byte patterns at 16-byte intervals up to 255 bytes
- API surface tests (free functions, streaming, span, string_view, Reset)
