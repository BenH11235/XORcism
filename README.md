# Introduction

XORcism is a FOSS command-line tool that breaks "rotating xor" style ciphers. It is written in [Rust](https://www.rust-lang.org/), with a moderate emphasis on test cases, parallelism, running time and memory efficiency. XORcism takes about 6 seconds on a standard laptop to decrypt a full bible that's been encrypted with a 975-byte key, which you're invited to try for yourself (`xorcism tora_cipher_975.bin`).

Xorcism supports both xor and modulo-2^32-addition based encryption. Support for modulo-947 multiplication of non-null bytes can easily be added, if that sort of thing ever becomes popular.

XORcism is likely to fail if:
    * The distribution of the plaintext characters is not known in advance
    * The distribution of the plaintext characters is high-entropy
    * The ciphertext is statistically anomalous
    * And various other scenarios 

A thorough theoretical analysis of XORcism's design, abilities and limitations can be found below, under "how the algorithm works".

Usage is simple and blunt; `xorcism <INPUT_FILE>` works. Try `xorcism --help` for various opt-in alphabet soup flags. The output is reproduced below, under "Usage". 

## Why did you write this?

1. It seemed like a good way to learn more Rust.
2. We took note of Halvar Flake's [Keynote Talk](https://www.sstic.org/media/SSTIC2018/SSTIC-actes/2018_ouverture/SSTIC2018-Slides-2018_ouverture-flake.pdf) at [SSTIC 2018](https://www.sstic.org) where he argues that tools in the RE community are closed-source, closed-binary, unit-test-free, memory-inefficient, throwaway single-threaded python "frameworks" with zero interoperability or separation of concerns, full of "deadline is tomorrow" hacks, written to check a box for a presentation that's full of non-reproducible examples and non-applicable hyperbolic claims.

#How does XORcism work?

//TODO


## Usage

```
xorcism [OPTIONS] <INPUT_FILE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --combination-function <COMB_FUNC>    Sets the assumed f where f(key_byte, plain_byte) = cipher_byte [default: xor]  [possible values: xor, add_mod_256]
    -k, --key-distribution <KEY_DIST>         Sets the assumed distribution of the key characters [default: uniform] [possible values: shakespeare, base64, hex, uniform]
    -o, --output_file <OUTPUT_FILE>           Sets the output file to write to [default: xorcism.out]
    -p, --plaintext-distribution <PT_DIST>    Sets the assumed distribution of the plaintext characters [default: shakespeare] [possible values: shakespeare, base64, hex, uniform]

ARGS:
    <INPUT_FILE>    Sets the input file to use
```

## History

TODO: Write history

## Questions?

@benherzog11235, benhe@checkpoint.com
