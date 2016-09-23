The JWK object
==============

# Overview

The JWK object represents a key. Depending on the key properties, it can be used to sign, verify a signature, encrypt or decrypt.

The class `Jose\Object\JWK` implements the interface `Jose\Object\JWKInterface` and provides the following methods:
* `get($name)`: get the value at key `$name`. Throws an exception if the key does not exist.
* `has($name)`: return true if the key has a key/value pair `$name`
* `getAll()`: get all key/value pairs
* `thumbprint($algorithm)`: returns the thumbprint of the key using the hash algorithm `$algorithm`. You can use any algorithm return by the `hash_algos()` method. 
* `toPublic()`: if the key is private (RSA or EC private key), this method returns the public key.

Note that a JWK object
* is serializable: You can call `json_encode($jwk)` to display the key set as a string (e.g. `{'kty':'oct', 'k':'abcdef...'}`).
* is immutable: you cannot modify it

# Create a `JWK` object

To create a `JWK` object, simply instantiate the class and set values.
Please note that the key/value pair `kty` MUST be set. 

```php
use `Jose\Object\JWK`;

$jwk = new JWK([
    'kty' => 'oct',
    'kid' => 'My First Key',
    'k'   => 'abcdef',
]);
```

# Key values

Each key must at least contain the parameter `kty` (key type).
Other values depend on the key type.

We recommend you to set the following values:
* `kid`: the unique key ID
* `use`: usage of the key (`sig` for signature/verification or `enc` for encryption/decryption)
* `alg`: the algorithm for which the key is dedicated

More details on [the JWK specification](http://tools.ietf.org/html/rfc7517#section-4).
You can use custom key/value pairs depending on your needs.

Unless otherwise stipulated, all required values are Base64 Url Safe encoded.

# None key (`none`)

This type of key does not require any other value.

```php
$jwk = new JWK([
    'kty' => 'none',
    'alg' => 'none', //Not mandatory, but as the key is only used with that algorithm this key/value pair is recommended
    'use' => 'sig',  //Not mandatory, but as the key is only used to sign JWT, this key/value pair is recommended
]);
```

# Symmetric key (`oct`)

This key type requires the following value:
* `k`: a binary string that represent the shared key.

```php
$jwk = new JWK([
    'kty' => 'oct',
    'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
]);
```

# Asymmetric key

*General Note: all private keys can use the method `toPublic()` to get the public key associated to the private one:*

```php
$public_key = $private_key->toPublic();
```

## RSA key (`RSA`)

`RSA` public and private keys are very similar.
The difference is that a public key only contains `n` (modulus) and `e` (exponent) values. These values are mandatory.
Private keys will also contain values `d`, `p` and `q`. They may also contain other prime values (`dp`, `dq` and `qi`)

```php
// A public key
$jwk = new JWK([
    'kty' => 'RSA',
    'n'   => 'sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw',
    'e'   => 'AQAB',
]);
```

```php
// A private key
$jwk = new JWK([
    'kty' => 'RSA',
    'n'   => 'sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw',
    'e'   => 'AQAB',
    'd'   => 'VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ',
    'p'   => '9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM',
    'q'   => 'uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0',
    'dp'  => 'w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs',
    'dq'  => 'o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU',
    'qi'  => 'eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo',
]);
```

## ECC key (`EC`)

`ECC` public and private keys are very similar.
The difference is that a public key only contains `crv` (curve), `x` and `y` values. These values are mandatory.
Private keys will also contain a value `d`.

The value `crv` is not Base64 Url Safe encoded.

```php
// A public key
$jwk = new JWK([
    'kty' => 'EC',
    'crv' => 'P-521',
    'x'   => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
    'y'   => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
]);
```

```php
// A private key
$jwk = new JWK([
    'kty' => 'EC',
    'crv' => 'P-521',
    'x'   => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
    'y'   => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
    'd'   => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
]);

```

Supported curves are `P-256`, `P-384` and `P-521`.

## Octet key pair (`OKP`)

This key type is used by the EdDSA algorithms.
- signature with curves Ed25519 and Ed448
- encryption with curves X25519 nd X448

At the moment, only Ed25519 and X25519 curves are supported.

Public keys must contain `crv` (curve) and `x` values.
Private keys will also contain a value `d`.

The value `crv` is not Base64 Url Safe encoded.

```php
// A private OKP key
$public = new JWK([
   'kty' => 'OKP',
   'crv' => 'Ed25519',
   'x'   => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
]);

// A private OKP key
$private = new JWK([
   'kty' => 'OKP',
   'crv' => 'Ed25519',
   'x'   => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
   'd'   => 'nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A',
]);
```

# JWK Methods

```php
use `Jose\Object\JWK`;

$jwk = new JWK([
    'kty' => 'oct',
    'k'   => 'abcdef',
]);

$this->has('kty'); // Return true
$this->has('foo'); // Return false
$this->get('kty'); // Return 'oct'
$this->thumbprint('sha256'); // Return 'iBLRjibnjP0qSVQ2TnyD_CYLXSNz5hjwjLMdUkY-JQg'
$this->get('foo'); // Throws an exception as this key/value pair does not exist
```

# Key Factory

Your keys may be stored in a file (X509 certificate, PEM key or DER key) or are available through an URL.
You can easily load and create keys from several sources using the `Jose\Factory\JWKFactory` factory provided with this library.

## Create a Key from Values

You may need this method to create keys when you already have values (symmetric keys):

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromValues([
    'kty' => 'oct',
    'k'   => 'GawgguFyGrWKav7AX4VKUg',
]);
```

## Create a Key from a X509 Certificate File

Use this method to load a certificate an convert it into a JWK object.
The second argument allow you to add key/value pairs.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromCertificateFile('/path/to/the/certificate', ['use' => 'sig', 'alg'=> 'RS256']);
```

*Please note that the key/value pairs `x5t` (SHA-1 thumbprint) and `x5t#256` (SHA-256 thumbprint) are automatically added* 

The factory is able to load X509 Certificates store in PEM or DER format. This is done automatically.
This library also supports files that contain a certificate chain. In this case, all the chain is verified.

## Create a Key from a X509 Certificate

You can create a key file with an already loaded certificate file.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromCertificate($file_content, ['use' => 'sig', 'alg'=> 'RS256']);
```

*Please note that the key/value pairs `x5t` (SHA-1 thumbprint) and `x5t#256` (SHA-256 thumbprint) are automatically added*

## Create a Key from a X509 Certificate Resource

You can create a key file with an already loaded certificate file using the certificate resource.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromX509Resource($resource, ['use' => 'sig', 'alg'=> 'RS256']);
```

*Please note that the key/value pairs `x5t` (SHA-1 thumbprint) and `x5t#256` (SHA-256 thumbprint) are automatically added*

## Create a Key from a key file

This factory can load a key stored in a file.
Both PEM and DER formats are supported. If the key is encrypted, the secret must be passed (2nd argument).
Additional parameters can be set (3rd argument).

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromKeyFile('/path/to/the/key', 'secret', ['use' => 'sig', 'alg'=> 'RS256']);
```

## Create a Key from a key file content

You can create a key file with an already loaded key file.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromKey($file_content, 'secret', ['use' => 'sig', 'alg'=> 'RS256']);
```


## Create a Key from a X5C header parameter

If you load a JWT and it contains a header with key `X5C`, you can load this certificate to get the associated public key.
It is recommended to use this parameter only if it is protected.

In the following example, the variable `$jws` is a valid `JWS` object with one signature. Its protected header contain a `X5C` parameter.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createFromX5C($jws->getSignature(0)->getProtectedHeader('x5c'));
```

## Create a Random Key

The `JWKFactory` is able to easily create random keys. At the moment, the factory supports the following key types:

* `oct` (key size depends on the signature/encryption algorithm).
* `RSA` (key size depends on the signature/encryption algorithm).
* `EC` with curves `P-256`, `P-384` and `P-521`.
* `OKP` with curves `Ed25519` and `X25519`.

### Create a Random `oct` Key

The following example will create an `oct` key.
The key size is 256 bits (`'size' => 256`) and that key will be used with the `HS256` algorithm for signature/verification only.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createKey([
        'kty'  => 'oct',
        'size' => 256,
        'kid'  => 'KEY1',
        'alg'  => 'HS256',
        'use'  => 'sig',
]);
```

### Create a Random `RSA` Key

The following example will create a `RSA` key.
The key size is 4096 bits and that key will be used with the `RSA-OAEP` algorithm for encryption/decryption only.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createKey([
        'kty'  => 'RSA',
        'size' => 4096,
        'kid'  => 'KEY1',
        'alg'  => 'RSA-OAEP',
        'use'  => 'enc',
]);
```

### Create a Random `EC` Key

The following example will create an `EC` key.
The key uses the `P-521` curve and will be used with the `ES512` algorithm for signature/verification only.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createKey([
        'kty' => 'EC',
        'crv' => 'P-521',
        'kid' => 'KEY1',
        'alg' => 'ES512',
        'use' => 'sig',
]);
```

### Create a Random `OKP` Key

The following example will create an `OKP` key.
The key uses the `X25519` curve and will be used with the `ECDH-ES` algorithm for encryption/decryption only.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createKey([
        'kty' => 'OKP',
        'crv' => 'X25519',
        'kid' => 'KEY1',
        'alg' => 'ECDH-ES',
        'use' => 'enc',
]);
```

### Create a Random `None` Key

This is not really a random key as the `none` key type does not contain any random key/value pair.
However you may need to create such key the same way you create other keys.

The key will at least contain the `kty` and the `alg` key with value `none` and the key `use` with `sig` as this kind of kind can only be used to sign JWT using the `none` algorithm.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createKey([
        'kty' => 'none',
        'kid' => 'KEY1',
]);
```

## Create a Storable Key

Keys created with the `createKey` method of the JWKFactory are created randomly.
You may need to store those keys for futur needs.

```php
use Jose\Factory\JWKFactory;

$rotatable_key = JWKFactory::createStorableKey(
    '/path/to/the/storage/file.key', // The file which will contain the key
    [
        'kty' => 'OKP',
        'crv' => 'X25519',
        'alg' => 'ECDH-ES',
        'use' => 'enc',
    ]
);
```

If the destination file is deleted, the file is automatically recreated on demand.
If you want to generate a new key after a period of time, you should use the Rotatable Keys,
however by deleting the file you can have the same result but you can decide to renew the key at any time.

## Create a Rotatable Key

Some applications may require that the keys change after a period of time.
This library is able to generate and manage these keys without effort.

```php
use Jose\Factory\JWKFactory;

$rotatable_key = JWKFactory::createRotatableKey(
    '/path/to/the/storage/file.key', // The file which will contain the key
    [
        'kty' => 'OKP',     // Key specifications
        'crv' => 'X25519',  // Please note that the parameter 'kid' automatically set by the factory.
        'alg' => 'ECDH-ES',
        'use' => 'enc',
    ],
    3600                    // This key will change after 3600 seconds (1 hour)
);
```

The key can be used like any other keys. After 3600 seconds, the values of that key will be updated.
If the key exists in the storage and is not expired then it is loaded.
