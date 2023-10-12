# HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

HKDF is designed to be a relatively straightforward way to derive keys from one or more pieces of input data.

HKDF follows the "extract-then-expand" paradigm, where it extracts a fixed-size key from the input (possibly randomizing it in the process), and then expands it to the desired length.

## Key Derivation Function (KDF) Overview

A Key Derivation Function is used to derive cryptographic keys from secret values such as passwords or other keys.
The derived keys can then be used for various cryptographic purposes, such as encryption or authentication.

A primary use case of KDFs is to take non-uniformly distributed secret data (like user passwords) and produce a uniformly distributed secret key. KDFs can also be used to derive multiple keys from a single secret value, allowing for keys with different purposes to be generated from a single source.

HKDF, in particular, follows the "extract-then-expand" paradigm:

1. Extract: Take any input of potentially any length and produce a fixed-size pseudorandom key from it.
2. Expand: Take the aforementioned key and produce one or more keys of the desired length.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     hkdf:
       github: spider-gazelle/hkdf
   ```

2. Run `shards install`

## Usage

```crystal
require "hkdf"
require "random"

# Extract phase
salt = Random.new.random_bytes(16)
ikm = "input key material".to_slice # Your input key material
prk = HKDF.extract(salt, ikm)

# Expand phase
info = "some context".to_slice # Optional context and application-specific information
length = 32 # Desired length of the output keying material
okm = HKDF.expand(prk, info, length)

# Combined HKDF Extract-and-Expand
derived_key = HKDF.derive_key(salt, ikm, info, length)
derived_key == okm
```

## Contributors

- [Stephen von Takach](https://github.com/stakach) - creator and maintainer
