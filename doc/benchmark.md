Benchmarks
==========

You can easily check if an algorithm is fast enough on your platform.
This project has tests for all operations with (almost) all algorithms.

# All algorithms

To run those tests, you must install the library with all dev dependencies.
When done, just run the following command:

```sh
./vendor/bin/phpbench run --store
```

**The previous command will test ALL algorithms and may take more than 7 hours.**

# Algorithm Selection

We recommend you to run tests only for the algorithm(s) you want to use.
Just run the following command:

```sh
./vendor/bin/phpbench run --group GROUP --store
```

The value of `GROUP` should be one of the following values:

* All signature algorithms: `JWS`
    * All HMAC algorithms: `hmac`
        * HS256: `HS256`
        * HS384: `HS384`
        * HS512: `HS512`
    * All Elliptic Curves algorithms: `ECDSA`
        * ES256: `ES256`
        * ES384: `ES384`
        * ES512: `ES512`
    * All Edwards-curve algorithms: `EdDSA`
        * Ed25519: `Ed25519`
    * All RSA algorithms: `RSASign`
        * RS256: `RS256`
        * RS384: `RS384`
        * RS512: `RS512`
        * PS256: `PS256`
        * PS384: `PS384`
        * PS512: `PS512`
* All key encryption algorithms: `JWE`
    * `KW`
        * A128KW: `A128KW`
        * A192KW: `A192KW`
        * A256KW: `A256KW`
    * `GCMKW`
        * A128GCMKW: `A128GCMKW`
        * A192GCMKW: `A192GCMKW`
        * A256GCMKW: `A256GCMKW`
    * `ECDHES`
        * ECDH-ES: `ECDHES`
        * `ECDHESKW`
            * ECDHESA128KW: `ECDH-ES+A128KW`
            * ECDHESA192KW: `ECDH-ES+A192KW`
            * ECDHESA256KW: `ECDH-ES+A256KW`
    * `PBES2`
        * PBES2-HS256+A128KW: `PBES2HS256A128KW`
        * PBES2-HS384+A192KW: `PBES2HS384A192KW`
        * PBES2-HS512+A256KW: `PBES2HS512A256KW`
    * `RSAEnc`
        * RSA1_5: `RSA1_5`
        * RSA-OAEP: `RSA-OAEP`
        * RSA-OAEP-256: `RSA-OAEP-256`
    
* Note 1: the `dir` algorithm is not tested as there is no key encryption or key decryption with this algorithm.
* Note 2: tests consist in a full JWS/JWE creation and loading and sometimes using multiple key sizes.
* Note 3: for JWE creation and loading, each key encryption algorithm is tested with the following content encryption algorithms:
    * `A128GCM`, `A192GCM` and `A256GCM`
    * `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`

# Examples

Test all HMAC algorithms:

```sh
./vendor/bin/phpbench run --group hmac --store
```

Test the RSA1_5 algorithm:

```sh
./vendor/bin/phpbench run --group RSA1_5 --store
```

# Benchmark Details

The result of the following command will only give you partial result. For example:

```sh
PhpBench 0.13.0. Running benchmarks.
Using configuration file: phpbench.json

............

12 subjects, 12 iterations, 12,000 revs, 0 rejects
(best [mean mode] worst) = 31.275 [86.783 86.783] 31.275 (μs)
⅀T: 1,041.395μs μSD/r 0.000μs μRSD/r: 0.000%
Storing results ... OK
Run: 133c8a853cf321f0b7b63e4e60f819f9910e1285
```

The main information is that the best algorithm takes only 31.275 µs... but you may need more information.

Just run the following command:

```sh
./vendor/bin/phpbench report --report=simple --output=md --uuid=133c8a853cf321f0b7b63e4e60f819f9910e1285
```

*The value of the `--uuid` option is given at the end of the previous command. You can also use `latest`.

A `report.md` file will be created. It contains a detailed report (Markdown format). Example:

```md
Jose Performance Test Suite
===========================

### suite: 133c8a853cf321f0b7b63e4e60f819f9910e1285, date: 2017-09-20, stime: 22:05:45

benchmark | groups | subject | mean
 --- | --- | --- | --- 
HS256Bench | JWS,hmac,HS256 | benchSignature | 104.450μs
HS256Bench | JWS,hmac,HS256 | benchVerification | 161.093μs
HS384Bench | JWS,hmac,HS384 | benchSignature | 112.788μs
HS384Bench | JWS,hmac,HS384 | benchVerification | 161.978μs
HS512Bench | JWS,hmac,HS512 | benchSignature | 105.686μs
HS512Bench | JWS,hmac,HS512 | benchVerification | 163.139μs
```

If it is not enough for you, you can get a full report with the following command:

```sh
./vendor/bin/phpbench report --report=default --output=md --uuid=133c8a853cf321f0b7b63e4e60f819f9910e1285
```
