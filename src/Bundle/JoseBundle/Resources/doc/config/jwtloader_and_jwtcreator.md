JWT Creator and JWT Loader Services
===================================

# JWT Creator

A JWT Creator service is a service that provides a `Jose\JWTCreatorInterface` object that allow you to easily
sign or encrypt (or both) at once and get a JWT in Compact Serialization Mode (the most common JWT representation).

In fact, it is just a service that needs a `Signer` and, if encryption is needed, an `Encrypter`.

In the following example, the JWT Creator service will be available through `jose.jwt_creator.jwt_CREATOR1`:

```yml
jose:
    jwt_creators:
        CREATOR1: # ID of the JWT Creator. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            signer: 'jose.signer.SIGNER1' # The name of the Signer service
            encrypter: 'jose.encrypter.ENCRYPER1' # Optional. The name of the Encryper service. Only needed if you want to create Compact JWE
```

As you noted, you need to have a valid Signer service and optionally an Encrypter service.
This bundle provides another way to create a JWT Creator by setting the algorithms you need.
It will automatically create the Signer and the Encrypter (if needed) with all algorithms you selected.

In the following example, the JWT Creator service will be available through `jose.jwt_creator.jwt_CREATOR1`:

```yml
jose:
    easy_jwt_creator:
        CREATOR1:
            is_public: true
            signature_algorithms:
                - 'HS256'
                - 'HS384'
                - 'HS512'
            key_encryption_algorithms: # Optional
                - 'A256GCMKW'
                - 'RSA-OAEP'
            content_encryption_algorithms: # Optional
                - 'A256GCM'
            compression_methods: # Optional
                - 'DEF'
```

# JWT Loader

A JWT Loader service is a service that provides a `Jose\JWTLoaderInterface` object that allow you to easily
decrypt (if decryption is supported) and verify at once and get a `Jose\JWSInterface` object.

In fact, it is just a service that needs a `Decryper` (optional), a `Verifier` and a `Checker`.

In the following example, the JWT Loader service will be available through `jose.jwt_loader.jwt_LOADER1`:

```yml
jose:
    jwt_loaders:
        LOADER1: # ID of the JWT Loader. Must be unique
            is_public: true # The service created by the bundle will be public (default)
            verifier: 'jose.verifier.VERIFIER1' # The name of the Verifier service
            checker: 'jose.checker.CHECKER1' # The name of the Checker service
            decrypter: 'jose.decrypter.DECRYPER1' # Optional. The name of the Decryper service. Only needed if you want to load Compact JWE
```

As you noted, you need to have a valid Verifier and Checker services and optionally an Decrypter service.
This bundle provides another way to create a JWT Loader by setting the algorithms you need.
It will automatically create the Verifier, a Checker and the Decrypter (if needed) with all algorithms you selected.

In the following example, the JWT Loader service will be available through `jose.jwt_loader.jwt_LOADER1`:

```yml
jose:
    easy_jwt_loader:
        LOADER1:
            is_public: true
            signature_algorithms:
                - 'HS256'
                - 'HS384'
                - 'HS512'
            key_encryption_algorithms: # Optional
                - 'A256GCMKW'
                - 'RSA-OAEP'
            content_encryption_algorithms: # Optional
                - 'A256GCM'
            header_checkers: # Optional
                - 'crit'
            claim_checkers: # Optional
                - 'exp'
                - 'iat'
                - 'nbf'
            compression_methods: # Optional
                - 'DEF'
```
