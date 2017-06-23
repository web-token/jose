Signers and Verifiers Services
==============================

# Signers

A Signer is a service that provides functions to sign payloads according to the headers (protected or unprotected) and private or shared keys.

Each Signer you create is available as a service you can inject in your own services or use from the container.
It is allowed to use a set of algorithms you explicitly defined.

In the following example, we create two Signers.
They will be available through `jose.signer.SIGNER1` and `jose.signer.SIGNER2` respectively:

```yml
jose:
    signers:
        SIGNER1: # ID of the Signer. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            algorithms: # A list of algorithms (see below for the complete list)
                - 'HS256'
                - 'HS384'
                - 'HS512'
        SIGNER2: # ID of the Signer. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            algorithms: # A list of algorithms (see below for the complete list)
                - 'RS256'
                - 'RS512'
                - 'PS256'
                - 'PS512'
```

# Verifiers

A Verifier is a service that provides functions to verify the JWS you received using public or shared keys.

As Signers, each Verifier you create is available as a service you can inject in your own services or use from the container. It is allowed to use a set of algorithms you explicitly defined.

In the following example, we create one Verifier. It will be available through `jose.verifier.VERFIER1`:

```yml
jose:
    verifiers:
        VERFIER1: # ID of the Verifier. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            algorithms: # A list of algorithms (see below for the complete list)
                - 'HS256'
                - 'HS384'
                - 'HS512'
```

# Signer & Verifier at Once

In some cases, you will need a signer and a verifier with the same set of algorithms.
There is a configuration option `create_verifier` you can use to create both services at once:

```yml
jose:
    signers:
        SERVICE1: # ID of the Signer. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            create_verifier: true
            algorithms: # A list of algorithms (see below for the complete list)
                - 'HS256'
                - 'HS384'
                - 'HS512'
```

This will automatically create the services `jose.signer.SERVICE1` and `jose.verifier.SERVICE1`.
Both services will support `HS256`, `HS384` and `HS512` algorithms.

# Supported Signature Algorithms

Hereafter the list of all algorithms supported by this library.

You may need an additional algorithm, then [read that page](../next/custom_algorithm.md) to know how to create custom algorithms.

* [x] `HS256`, `HS384`, `HS512`
* [x] `ES256`, `ES384`, `ES512`
* [x] `RS256`, `RS384`, `RS512`
* [x] `PS256`, `PS384`, `PS512`
* [x] `none` (**Please note that this is not a secured algorithm. DO NOT USE IT PRODUCTION!**)
* [x] `EdDSA`
    * [x] With `Ed25519` curve ([third party extension required](https://github.com/encedo/php-ed25519-ext))
    * [ ] With `Ed448` curve

*Please note that the [EdDSA signature algorithm specification](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves)
is not not yet approved. Support for the algorithm `EdDSA` with `Ed25518` and `Ed448` curves may change. Use with caution.*
