Encrypters and Decrypters Services
==================================

# Encrypters

An Encrypter is a service that provides methods to encrypt payloads according to the headers (protected or unprotected) and public or shared keys.

Each Encrypter you create is available as a service you can inject in your own services or use from the container.
It is allowed to use a set of algorithms you explicitly defined.

In the following example, we create an Encrypter that will be available through `jose.encrypter.ENCRYPTER1`:

```yml
jose:
    encrpters:
        ENCRYPTER1: # ID of the Encrypter. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            key_encryption_algorithms: # A list of algorithms used for the encryption of the key (see below for the complete list)
                - '128GCMKW'
                - 'A256GCMKW'
                - 'RSA-OAEP'
            content_encryption_algorithms: # A list of algorithms used for the encryption of the content (see below for the complete list)
                - 'A128GCM'
                - 'A256GCM'
            compression_methods: # A list of compression methods (see below for the complete list)
                - 'DEF' # Deflate compression mode (set by default)
```

# Decrypters

A Decrypter is a service that provides functions to decrypt JWE you received using private or shared keys.

As Encrypters, each Decrypter you create is available as a service you can inject in your own services or use from the container.
It is allowed to use a set of algorithms you explicitly defined.

In the following example, we create a Decrypter. It will be available through `jose.verifier.DECRYPTER1`:

```yml
jose:
    decrypters:
        DECRYPTER1: # ID of the Decrypter. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            key_encryption_algorithms: # A list of algorithms used for the encryption of the key (see below for the complete list)
                - '128GCMKW'
                - 'A256GCMKW'
                - 'RSA-OAEP'
            content_encryption_algorithms: # A list of algorithms used for the encryption of the content (see below for the complete list)
                - 'A128GCM'
                - 'A256GCM'
            compression_methods: # A list of compression methods (see below for the complete list)
                - 'DEF' # Deflate compression mode (set by default)
```

# Encrypter & Decrypter at Once

In some cases, you will need a encrypt and a decrypt with the same set of algorithms.
There is a configuration option `create_decrypter` you can use to create both services at once:

```yml
jose:
    encrypters:
        SERVICE1: # ID of the Encrypter. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            create_decrypter: true
            key_encryption_algorithms: # A list of algorithms used for the encryption of the key (see below for the complete list)
                - '128GCMKW'
                - 'A256GCMKW'
                - 'RSA-OAEP'
            content_encryption_algorithms: # A list of algorithms used for the encryption of the content (see below for the complete list)
                - 'A128GCM'
                - 'A256GCM'
            compression_methods: # A list of compression methods (see below for the complete list)
                - 'DEF' # Deflate compression mode (set by default)
```

This will automatically create the services `jose.encrypter.SERVICE1` and `jose.decrypter.SERVICE1`.
Both services will support the same encryption algorithms and compression methods.

# Supported Encryption Algorithms

Hereafter the list of all algorithms supported by this library.

You may need an additional algorithm, then [read that page](../next/custom_algorithm.md) to know how to create custom algorithms.

## Key Encryption Algorithms

* [x] `dir`
* [x] `RSA1_5`
* [x] `RSA-OAEP`
* [x] `RSA-OAEP-256`
* [x] `ECDH-ES`
* [x] `ECDH-ES+A128KW`
* [x] `ECDH-ES+A192KW`
* [x] `ECDH-ES+A256KW`
* [x] `A128KW`
* [x] `A192KW`
* [x] `A256KW`
* [x] `PBES2-HS256+A128KW`
* [x] `PBES2-HS384+A192KW`
* [x] `PBES2-HS512+A256KW`
* [x] `A128GCMKW` (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] `A192GCMKW` (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] `A256GCMKW` (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] `EdDSA`
    * [x] With `X25519` curve ([third party extension required](https://github.com/encedo/php-curve25519-ext))
    * [ ] With `X448` curve

*Please note that the [EdDSA encryption algorithm specification](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves)
is not not yet approved. Support for the algorithm `EdDSA` with `X25518` and `X448` curves may change. Use with caution.*

## Supported Content Encryption Algorithms

* [x] `A128CBC-HS256`
* [x] `A192CBC-HS384`
* [x] `A256CBC-HS512`
* [x] `A128GCM` (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] `A192GCM` (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))
* [x] `A256GCM` (for performance, this [third party extension is highly recommended](https://github.com/bukka/php-crypto))

# Supported Compression Methods

Hereafter the list of all compression methods supported by this library.

You may need an additional compression method, then [read that page](../next/custom_compression_method.md) to know how to create custom compression methods.

* [x] `DEF`: Deflate
* [x] `ZLIB`: ZLib (not described in the RFCs, for internal use only)
* [x] `GZ`: GZip (not described in the RFCs, for internal use only)
