PHP JOSE Library
================

If you really love that library, then you can help me out for a couple of :beers:!

[![Beerpay](https://beerpay.io/Spomky-Labs/jose/badge.svg?style=beer-square)](https://beerpay.io/Spomky-Labs/jose)  [![Beerpay](https://beerpay.io/Spomky-Labs/jose/make-wish.svg?style=flat-square)](https://beerpay.io/Spomky-Labs/jose?focus=wish)

----

<p align="center">:warning::warning::warning:</p>

We highly recommend you to use the new [JWT Framework project](https://github.com/web-token/jwt-framework) instead of this library.

* Active support of this library is provided until **end of 2018**.
* Security support will be provided **from 2019 and up to end of 2020**.

A migration guide will be/is available in [the documentation of the new project](https://web-token.spomky-labs.com/migration/from-spomky-labs-jose).

<p align="center">:warning::warning::warning:</p>

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/jose/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/jose/?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/Spomky-Labs/jose/badge.svg?branch=master)](https://coveralls.io/github/Spomky-Labs/jose?branch=master)

[![Build Status](https://travis-ci.org/Spomky-Labs/jose.svg?branch=master)](https://travis-ci.org/Spomky-Labs/jose)
[![HHVM Status](http://hhvm.h4cc.de/badge/Spomky-Labs/jose.svg?style=flat)](http://hhvm.h4cc.de/package/Spomky-Labs/jose)
[![PHP 7 ready](http://php7ready.timesplinter.ch/Spomky-Labs/jose/badge.svg)](https://travis-ci.org/Spomky-Labs/jose)

[![Dependency Status](https://www.versioneye.com/user/projects/57ac28c489a9740034ca18c6/badge.svg?style=flat-square)](https://www.versioneye.com/user/projects/57ac28c489a9740034ca18c6)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee/big.png)](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee)

[![Latest Stable Version](https://poser.pugx.org/Spomky-Labs/JOSE/v/stable.png)](https://packagist.org/packages/Spomky-Labs/JOSE)
[![Total Downloads](https://poser.pugx.org/Spomky-Labs/JOSE/downloads.png)](https://packagist.org/packages/Spomky-Labs/JOSE)
[![Latest Unstable Version](https://poser.pugx.org/Spomky-Labs/JOSE/v/unstable.png)](https://packagist.org/packages/Spomky-Labs/JOSE)
[![License](https://poser.pugx.org/Spomky-Labs/JOSE/license.png)](https://packagist.org/packages/Spomky-Labs/JOSE)

This library provides an implementation of:

* JW**S** [JSON Web Signature (RFC 7515)](https://tools.ietf.org/html/rfc7515),
* JW**T** [JSON Web Token (RFC 7519)](https://tools.ietf.org/html/rfc7519),
* JW**E** [JSON Web Encryption (RFC 7516)](http://tools.ietf.org/html/rfc7516),
* JW**A** [JSON Web Algorithms (RFC 7518)](http://tools.ietf.org/html/rfc7518).
* JW**K** [JSON Web Key (RFC 7517)](http://tools.ietf.org/html/rfc7517).
* JSON Web Key Thumbprint ([RFC 7638](https://tools.ietf.org/html/rfc7638)).
* Unencoded Payload Option [RFC7797](https://tools.ietf.org/html/rfc7797).

# Provided Features

## Supported Input Types:

JWS or JWE objects support every input that can be encoded into JSON:

* [x] `string`, `array`, `integer`, `float`...
* [x] Objects that implement the `\JsonSerializable` interface such as `JWKInterface` or `JWKSetInterface`

The [detached content](https://tools.ietf.org/html/rfc7515#appendix-F) is also supported.

Unencoded payload is supported. This means you can sign and verify payload without base64 encoding operation.
As per the [RFC7797](https://tools.ietf.org/html/rfc7797), the `b64` header MUST be protected.
When `b64` header is set, the `crit` protected header with value `b64` in its array of values is mandatory.

## Supported Serialization Modes

* [x] Compact JSON Serialization Syntax (JWS/JWE creation and loading)
* [x] Flattened JSON Serialization Syntax (JWS/JWE creation and loading)
* [x] General JSON Serialization Syntax (JWS/JWE creation and loading)

## Supported Compression Methods

| Compression Method | Supported | Comment                                                         |
| ------------------ |:---------:| --------------------------------------------------------------- |
| Deflate (`DEF`)    | YES       |                                                                 |
| GZip (`GZ`)        | YES       | *This compression method is not described in the specification* |
| ZLib (`ZLIB`)      | YES       | *This compression method is not described in the specification* |

## Supported Key Types (JWK)

| Key Type | Supported | Comment                                      |
| -------- |:---------:| -------------------------------------------- |
| `none`   | YES       |  None keys are for the `none` algorithm only |
| `oct`    | YES       | Symmetric keys                               |
| `RSA`    | YES       | RSA based asymmetric keys                    |
| `EC`     | YES       | Elliptic Curves based asymmetric keys        |
| `OKP`    | YES       | Octet Key Pair based asymmetric keys         |

JWK objects support JSON Web Key Thumbprint ([RFC 7638](https://tools.ietf.org/html/rfc7638)).

## Key Sets (JWKSet)

JWKSet is fully supported.

## Supported Signature Algorithms

| Signature Algorithm            | Supported | Comment                                                                     |
| ------------------------------ |:---------:| --------------------------------------------------------------------------- |
| `HS256`, `HS384` and `HS512`   | YES       |                                                                             |
| `HS256`, `ES384` and `ES512`   | YES       |                                                                             |
| `RS256`, `RS384` and `RS512`   | YES       |                                                                             |
| `PS256`, `PS384` and `PS512`   | YES       |                                                                             |
| `none`                         | YES       | **Please note that this is not a secured algorithm. USE IT WITH CAUTION!**  |
| *`EdDSA` with `Ed25519` curve* | YES       | [Third party extension required](https://github.com/encedo/php-ed25519-ext) |
| *`EdDSA` with `Ed448` curve*   | **NO**    |                                                                             |

*Please note that the [EdDSA signature algorithm specification](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves)
is not not yet approved. Support for algorithms `Ed25518` and `Ed448` may change. Use with caution.*

## Supported Key Encryption Algorithms

| Key Encryption Algorithm                                            | Supported | Comment                                                                                                           |
| ------------------------------------------------------------------- |:---------:| ----------------------------------------------------------------------------------------------------------------- |
| `dir`                                                               | YES       |                                                                                                                   |
| `RSA1_5`, `RSA-OAEP` and `RSA-OAEP-256`                             | YES       |                                                                                                                   |
| `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW` and `ECDH-ES+A256KW`  | YES       |                                                                                                                   |
| `A128KW`, `A128KW` and `A128KW`                                     | YES       |                                                                                                                   |
| `PBES2-HS256+A128KW`, `PBES2-HS384+A192KW` and `PBES2-HS512+A256KW` | YES       |                                                                                                                   |
| `A128GCMKW`, `A192GCMKW` and `A256GCMKW`                            | YES       | For better performance, please use PHP 7.1+ or this [third party extension ](https://github.com/bukka/php-crypto) |
| `EdDSA` with `X25519` curve                                         | YES       | [Third party extension required](https://github.com/encedo/php-curve25519-ext)                                    |
| `EdDSA` with `X448` curve                                           | **NO**    |                                                                                                                   |

*Please note that the [EdDSA encryption algorithm specification](https://tools.ietf.org/html/draft-ietf-jose-cfrg-curves)
is not not yet approved. Support for algorithms `X25518` and `X448` may change. Use with caution.*

## Supported Content Encryption Algorithms

| Content Encryption Algorithm                         | Supported | Comment                                                                                                          |
| ---------------------------------------------------- |:---------:| ---------------------------------------------------------------------------------------------------------------- |
| `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512` | YES       |                                                                                                                  |
| `A128GCM`, `A192GCM` and `A256GCM`                   | YES       | For better performance, please use PHP 7.1+ or this [third party extension](https://github.com/bukka/php-crypto) |

# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least:
* ![PHP 7.0+](https://img.shields.io/badge/PHP-7.0%2B-ff69b4.svg),
* OpenSSL extension.

Please consider the following optional requirements:
* For AES-GCM based algorithms (`AxxxGCM` and `AxxxGCMKW`) if not on PHP 7.1+: [PHP Crypto](https://github.com/bukka/php-crypto) Extension (at least `v0.2.1`) is highly recommended as encryption/decryption is faster than the pure PHP implementation.
* For Ed25519 algorithm: [php-ed25519-ext](https://github.com/encedo/php-ed25519-ext) required
* For X25519 algorithm: [php-curve25519-ext](https://github.com/encedo/php-curve25519-ext) required

Please read performance test results below concerning the ECC based algorithms.
As the time needed to perform operation is long compared to the other algorithms, we do not recommend their use.

# Continuous Integration

It has been successfully tested using `PHP 7.0`, `PHP 7.1` and `PHP7.2` with all algorithms.
If you use PHP 5.6, please install the version ^6.0 of this project.

Tests vectors from the [RFC 7520](http://tools.ietf.org/html/rfc7520) are fully implemented and all tests pass.

We also track bugs and code quality using [Scrutinizer-CI](https://scrutinizer-ci.com/g/Spomky-Labs/JOSE) and [Sensio Insight](https://insight.sensiolabs.com/projects/9123fbfc-7ae1-4d63-9fda-170b8ad794ee).

Coding Standards are verified by [StyleCI](https://styleci.io/repos/22874677).

Code coverage is analyzed by [Coveralls.io](https://coveralls.io/github/Spomky-Labs/jose).

# Installation

The preferred way to install this library is to rely on Composer:

```sh
composer require spomky-labs/jose
```

# How to use

Have a look at [How to use](doc/Use.md) to know how to load your JWT and discover all possibilities provided by this library.

# Performances

Please read the [performance page](doc/Performance.md) to know how fast are the algorithms supported by this library.

# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome.
If you feel comfortable writting code, you could try to fix [opened issues where help is wanted](https://github.com/Spomky-Labs/jose/labels/help+wanted) or [those that are easy to fix](https://github.com/Spomky-Labs/jose/labels/easy-pick).

Do not forget to [follow these best practices](doc/Contributing.md).

# Licence

This software is release under [MIT licence](LICENSE).
