# fhsm-key-manager

Command-line tool for managing PBOC1/PBOC2 symmetric keys and RSA/SM2/ECC asymmetric keys. Byte-compatible with `fhsm-cpp` key files — reads and writes the exact same on-disk layout. Offline operation only: works on a stopped fhsm-cpp instance or a copy of its key directory (file I/O, no shared memory).

## Build

```sh
go build -o fhsm-key-manager .
```

Pure Go, zero external runtime dependencies, `CGO_ENABLED=0`.

## Command tree

```
fhsm-key-manager
  version                              # print version as JSON
  pboc1                                # manage PBOC1 symmetric keys (pboc1.key)
    get    --block --type --version --index
    get-all
    list
    put                                 # JSON from stdin (object or array)
    delete --block --type --version --index
  pboc2                                # manage PBOC2 symmetric keys (pboc2.key)
    get    --type --index --subtype
    get-all
    list
    put                                 # JSON from stdin (object or array)
    delete --type --index --subtype
  rsa                                  # manage RSA keys (rsa/NNNN.RSA)
    get    --index
    list
    put                                 # JSON from stdin
    delete --index
    gen    --index [--modlen N] [--exponent E]
  sm2                                  # manage SM2 keys (sm2/NNNN.SM2)
    get    --index
    list
    put                                 # JSON from stdin
    delete --index
    gen    --index
  ecc                                  # manage ECC keys (ecc/NNNN.ECC)
    get    --index                     # store/retrieve only — no gen (proprietary curve)
    list
    put                                 # JSON from stdin
    delete --index
```

## Global flags

| Flag       | Default                              | Description                                            |
| ---------- | ------------------------------------ | ------------------------------------------------------ |
| `--path`   | `.`                                  | Key root directory                                     |
| `--lsk`    | `0000...00` (32 hex = 16 zero bytes) | LSK hex (16 bytes) used for 3DES encryption of sym keys|
| `--verbose`| off                                  | Print progress to stderr                               |

## Output convention

- **stdout** is always JSON (indented).
- **stderr** is empty unless `--verbose` is set.
- **Exit code**: `0` on success, `1` on any error.
- On error the process prints a JSON envelope and exits `1`:

  ```json
  { "error": "<human-readable message>", "code": "<CODE>" }
  ```

  Common codes: `LSK_INVALID`, `KEY_NOT_FOUND`, `SIZE_MISMATCH`, `GEN_FAILED`, `INTERNAL`.

## Quick examples

Put a PBOC1 key (single object via stdin), then read it back:

```sh
echo '{"block":1,"type":1,"version":0,"index":1,"alg":0,"div":1,"exp":0,"length":16,
  "key":"01020304050607080102030405060708"}' \
  | ./fhsm-key-manager --path ./keys --lsk 11111111111111111111111111111111 pboc1 put

./fhsm-key-manager --path ./keys --lsk 11111111111111111111111111111111 \
  pboc1 get --block 1 --type 1 --version 0 --index 1
```

Generate an RSA keypair (1024-bit for quick tests; 2048 is the default):

```sh
./fhsm-key-manager --path ./keys rsa gen --index 1 --modlen 1024
```

Generate an SM2 keypair (sm2p256v1, pure-Go keygen):

```sh
./fhsm-key-manager --path ./keys sm2 gen --index 1
```

## Storage layout

All paths are relative to `--path`:

| File                      | Contents                                              |
| ------------------------- | ----------------------------------------------------- |
| `pboc1.key`               | PBOC1 symmetric key DB (2TDEA-encrypted slots)        |
| `pboc2.key`               | PBOC2 symmetric key DB (2TDEA-encrypted slots)        |
| `rsa/NNNN.RSA`            | RSA private key, PKCS#1 DER (`NNNN` = 4-digit index)  |
| `sm2/NNNN.SM2`            | SM2 keypair, raw `priv\|pubX\|pubY` (32+32+32 bytes)  |
| `ecc/NNNN.ECC`            | ECC key blob, raw `pri\|pub1\|pub2` (48+48+48 bytes)  |

## Binary format

The on-disk byte layout of every file matches `fhsm-cpp` exactly. For the full
specification (header structures, slot sizing, 2TDEA key derivation, reserved
bytes) see
[`docs/superpowers/specs/2026-06-27-fhsm-key-manager-design.md`](docs/superpowers/specs/2026-06-27-fhsm-key-manager-design.md).

## Notes

- **Byte-compatible with `fhsm-cpp`**: files produced by this tool load directly
  in fhsm-cpp and vice versa.
- **Offline only**: operate against a stopped fhsm-cpp or a copy of its key
  directory. The tool performs file I/O only and never touches shared memory.
- **LSK**: passed via `--lsk` rather than read from hardware; defaults to all-zero
  for test/dev environments. Use the same LSK value that fhsm-cpp is configured
  with, or decryption will fail.
- **ECC `gen` not supported**: the target curve is proprietary. ECC keys can be
  stored and retrieved (`put`/`get`/`list`/`delete`) but not generated.
