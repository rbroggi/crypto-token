![Build](https://github.com/rbroggi/crypto-token/actions/workflows/dockerimage.yml/badge.svg)
[![License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# Credit cards crypto-token engine

This repository contains a sample crypto-token engine implementation for
credit-cards. The tokens in this implementation have the following properties:

1. They preserve the byte length of a credit-card string representation. In other words,
they preserve the number of ascii characters that a text-based credit-card would have. Example:
    * CC `4444333322221111` -> TK `444433abcdef1111`
2. They contain only alpha-numeric characters `[0-9a-zA-Z]`
3. They preserve the first six and the last 4 digits of the credit-card. Example:
   * CC `4444333322221111` -> TK `444433abcdef1111`
4. They have one fixed character used for versioning purpose. This allows for automatic key-rotation strategies.
   In this implementation the character used for versioning is the first after the first 6 digits: 444433**a**bcdef1111
5. Different sized credit card tokens are encoded in different character-sets: we need to be able to encode the ciphered
   token in fewer bytes than the original middle-digits credit cards occupied, therefore we need a larger character-set (encoding base).
   Each token uses the minimum char-set base to be able to encode all possible credit cards while maintaining the same length. Below
   you can find a table with the Default character-set for each CC size 


| CC size | Encoding base | charset                                                         | Examples                                  |
|---------|---------------|-----------------------------------------------------------------|-------------------------------------------|
| 13      | 32            | a b c d e f g h i j k l m n o p q r s t u v w x y z 0 1 2 3 4 5 | 444433az02222, 444433bct2222              |
| 14      | 22            | a b c d e f g h i j k l m n o p q r s t u v                     | 444433abvk2222, 444433bctq2222            |
| 15      | 18            | a b c d e f g h i j k l m n o p q r                             | 444433abcqr2222, 444433befhi2222          |
| 16      | 16            | a b c d e f g h i j k l m n o p                                 | 444433abcaop2222, 444433befhike2222       |
| 17      | 15            | a b c d e f g h i j k l m n o                                   | 444433abcaooo2222, 444433befhikea2222     |
| 18      | 14            | a b c d e f g h i j k l m n                                     | 444433abcannnm2222, 444433befhikeae2222   |
| 19      | 14            | a b c d e f g h i j k l m n                                     | 444433abcannnam2222, 444433befhikseae2222 |


It's worth noticing that different character sets can be used, e.g. instead of using `a b c d e f g h i j k l m n` as base14 character set it would be 
perfectly fine to use `Z Y X W V T S R Q P O N M L`. In that case the token in the example `444433abcannnm2222` would be encoded as `444433aYXZLLLM2222`.

At the current situation the lib does not include Luhn digit-check, but one idea could be to use lower-case letters as alphabet for tokens and uppercase the last token letter in case 
of luhn-compliancy of the underlying encoded credit-card.

### Implementation

The current implementation makes use of [FF1](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf) [FPE](https://en.wikipedia.org/wiki/Format-preserving_encryption). All credits
due to the [golang ff1 implementation](https://github.com/capitalone/fpe). In addition to that, we use [HMAC](https://golang.org/pkg/crypto/hmac/)
golang standard library implementation for generating the tweak that the FF1 algorithm ingest. 
In the setup, each version has a cryptography key that is used for the FF1 FPE and one cryptography key that is used for HMAC.
The tokenization steps under a given version are:

1. Extract the credit-card `6x4` and HMAC it using the HMAC key for the version.
1. Using the HMAC as tweak, and the version encryption key, we encrypt the credit card middle-digits. As the FF1 algorithm is format preserving, the resulting cipher for 
   a n-digit string is itself another n-digit string. It's worth noticing that we use the HMAC as tweak so that different credit-cards sharing the same middle-digits 
   are unlike to share the same encryption cipher.
1. In order to maintain the number of byte-characters of the original credit-card **and** also encode the version byte into the token
   to allow detokenization, we use the smallest encoding base possible in order to be able to encode the n-digit string into a (n-1)-alpha string.
   The resulting token is the result of the concatenation of the following strings:
   1. credit card first 6 digits
   1. version byte character
   1. (n-1)-alpha encoded cipher
   1. credit-card last 4 digits 

The detokenization steps are:

1. Retrieve the 7-th char to identify the version and retrieve it's cryptographic keys (HMAC and FF1 encryption).
1. Extract the token `6x4` (same as the original credit-card) and HMAC it using the HMAC key for the version.
1. Decode the token middle-digits from the (n-1)-alpha base into a n-digit cipher.
1. Using the HMAC as tweak, and the version encryption key, we decrypt the token cipher. 
1. The resulting credit card is the result of the concatenation of the following strings:
   1. Token first 6 digits
   1. n-digit decrypted plaintext
   1. Token last 4 digits

### Unit-test, benchmark and build with docker

If you have docker installed you can build the container running the following command:

```bash
docker build -t crypto-token .
```

### Unit-test, benchmark and build in local

If you have Go and Make installed in your local environment you can refer the Makefile usage `make help` which gives insights around the possible commands.


A Makefile is provided to assist in building the application and running tests and benchmarks.

```console
$ make help
Usage:
  benchmem: runs processing and memory benchmarks
  bench   runs benchmarks
  build   builds the application
  clean   removes the binary
  help    prints this help message
  test    runs go test with default values
```

To run unit-tests, benchmarks and to build the binary you can run:

```bash
make test
make bench
make build
```

### Running

After building the program with either the _docker_ or the _local_ methods above you can run it. 

To run the application 2 types of command-line arguments can be provided: 


1. `input` is a comma-separated list of credit cards.
1. `separator` is the output-separator column separator.
1. `configuration` is a file-path to a configuration file in json format. For specific insights on the json file
    structure checkout the files in the `configs` folder.

You can also use a `-h` to have insights on the inputs.
Examples:

1. Invoke help:
   * local binary:
    ```console
    ./crypto-token -h
    ```
   * docker:
    ```console
    docker run -i crypto-token -h
    ```
   * output:
   ```console
   Usage of /go/src/app/crypto-token:
   -c string
        Engine configuration file path
   -i value
      Comma-separated list of credit-cards
   -s string
      Separator for the table output (default "|")
   ```
1. Nominal case with default separator and dummy engine (hardcoded versions and keys):
   * local binary:
    ```console
    ./crypto-token -i 4444333322221111,4444333322221112
    ```
   * docker:
    ```console
    docker run -i crypto-token -i 4444333322221111,4444333322221112
    ```
   * output (sample as output is not deterministic):
   ```console
   CC|TK
   4444333322221111|444433akeblg1111
   4444333322221112|444433bhbhkc1112
   ```
1. Nominal case with comma as separator:
   * local binary:
    ```console
    ./crypto-token -i 4444333322221111,4444333322221112 -s ,
    ```
   * docker:
    ```console
    docker run -i crypto-token -i 4444333322221111,4444333322221112 -s ,
    ```
   * output (sample as output is not deterministic):
   ```console
   CC,TK
   4444333322221111,444433dhdadp1111
   4444333322221112,444433dmgiaj1112
   ```
1. Nominal case with custom configuration:
   * local binary:
    ```console
    ./crypto-token -i 4444333322221111,4444333322221112 -c ./configs/sample-config-1.json
    ```
   * docker:
    ```console
    docker run -i crypto-token -i 4444333322221111,4444333322221112 -c ./configs/sample-config-1.json
    ```
   * output:
   ```console
   CC|TK
   4444333322221111|444433akeblg1111
   4444333322221112|444433aoiilg1112
   ```
