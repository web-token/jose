Configuration
=============

# Keys and Key Sets

Encryption/Decryption and Signature/Verification require **keys** or **key sets** to be done.
This bundle is able to load keys and key sets from various sources such as files (encrypted or not), certificates, URLs or values.

When loaded, the keys and key sets are available though services.

Please read  the following pages:
- [this page](config/keys.md) to know how to load your keys
- [this one](config/key_sets.md) for your key sets.

# Signers and Verifiers

The Signers and Verifiers services are used to **sign** and **verify** JWS objects.

You can create multiple services depending on your needs. For each service, selected algorithms may be different.
For example, you need a Signer to sign a JWS to be sent to clients using HS512 algorithm only and you need a Verifier
to verify requests from clients that use RS256 or ES384 algorithms.

Please read [this page](config/signers_and_verifiers.md) to know how to create your Signers and Verifiers Services.

# Checkers

The loaded JWS may contain claims such as expiration date, issuer... In this case, you must **verify** those claims before to use the JWS.
Checker managers can be created automatically using this bundle and are available though services.

Please read [this page](config/checkers.md) to know how to create your Checker Manager Services.

# Encrypters and Decrypters

The Encrypters and Decrypters services are used to **encrypt** and **decrypt** JWE objects.

Like Signers and Verifiers, you can create multiple services depending on your needs.
For each service, selected algorithms and compression methods may be different.

Please read [this page](config/encrypters_and_decrypters.md) to know how to create your Encrypters and Decrypters Services.

# JWT Creator and JWT Loader

Because you may need to:
* sign and encrypt at once
* decrypt, verify signature and check claims at once

Please read [this page](config/jwtloader_and_jwtcreator.md) to know how to create these services Services.
