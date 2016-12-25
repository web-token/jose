Sign Payload
============

This library provides several ways to digitally sign a payload (a message or a JWT).
In most cases, you will need to sign with only one key and export in JSON Compact Serialization Mode (a three parts Base64 encoded string separated with dots).

# The Easiest Way

A JWSFactory is available to ease all operations. We recommend to use it to create Compact JWS.
The minimum requirement is:

* the payload or claims (JWT) to sign
* the algorithm used to sign,
* a private or symmetric key ([`JWK` object](../object/jwk.md)) depending on the signature algorithm,

Example
-------

```php
use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;

// We load our key (JWK). It is an encrypted RSA key stored in a file
// Additional parameters ('kid', 'alg' and 'use') are set for this key (not mandatory but recommended).
$key = JWKFactory::createFromKeyFile(
    '/Path/To/My/RSA/private.encrypted.key',
    'Password',
    [
        'kid' => 'My Private RSA key',
        'alg' => 'RS256',
        'use' => 'sig',
    ]
);

// We want to sign the following claims
$claims = [
    'nbf'     => time(),        // Not before
    'iat'     => time(),        // Issued at
    'exp'     => time() + 3600, // Expires at
    'iss'     => 'Me',          // Issuer
    'aud'     => 'You',         // Audience
    'sub'     => 'My friend',   // Subject
    'is_root' => true           // Custom claim
];

$jws = JWSFactory::createJWSToCompactJSON(
    $claims,                      // The payload or claims to sign
    $key,                         // The key used to sign
    [                             // Protected headers. Muse contains at least the algorithm
        'crit' => ['exp', 'aud'],
        'alg'  => 'RS256',
    ]
);
```

Now the variable `$jws` contains a string that represents our JWS.

# The JWSFactory In Details

## Compact JWS with Detached Payload

In some contexts, it is useful to integrity-protect content that is not itself contained in a JWS.
The `JWSFactory` supports JWS and detached payload.

Example
-------

```php
use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;

// We load our key (JWK). It is an encrypted RSA key stored in a file
// Additional parameters ('kid', 'alg' and 'use') are set for this key (not mandatory but recommended).
$key = JWKFactory::createFromKeyFile(
    '/Path/To/My/RSA/private.encrypted.key',
    'Password',
    [
        'kid' => 'My Private RSA key',
        'alg' => 'RS256',
        'use' => 'sig',
    ]
);

// We want to sign the following claims
$claims = [
    'nbf'     => time(),        // Not before
    'iat'     => time(),        // Issued at
    'exp'     => time() + 3600, // Expires at
    'iss'     => 'Me',          // Issuer
    'aud'     => 'You',         // Audience
    'sub'     => 'My friend',   // Subject
    'is_root' => true           // Custom claim
];

$jws = JWSFactory::createJWSWithDetachedPayloadToCompactJSON(
    $claims,                      // The payload or claims to sign
    $key,                         // The key used to sign
    [                             // Protected headers. Muse contains at least the algorithm
        'crit' => ['exp', 'aud'],
        'alg'  => 'RS256',
    ]
);
```

Now the variable `$jws` contains a string that represents our JWS, but the payload is not included.

## Flattened JWS with/without Detached Payload

The flattened JWS JSON Serialization syntax is based upon the general syntax but flattens it, optimizing it for the single digital signature/MAC case..
You can produce such JWS the same way as Compact JWS.

The methods to use are `createJWSToFlattenedJSON` or `createJWSWithDetachedPayloadToFlattenedJSON`.

## Multiple Signatures

Compact and Flattened JWS allow only one signature. You may need to produce JWS with multiple signatures.
This is useful when you want to send at once a JWS to multiple audiences that support different algorithms.

Let say the audience `Audience 1` supports only `RS256` and the audience `Audience 2` supports `HS512`.

```php
use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;

// We load our key. It will be used to sign with algorithm RS256
$key1 = JWKFactory::createFromKeyFile(
    '/Path/To/My/RSA/private.encrypted.key',
    'Password',
    [
        'kid' => 'My Private RSA key',
        'use' => 'sig',
        'alg' => 'RS256',
    ]
);

// We load the second key to sign using algorithm HS512
$key2 = JWKFactory::createFromValues(
    [
        'kty' => 'oct',
        'kid' => 'My Shared key',
        'use' => 'sig',
        'alg' => 'HS512',
        'k'   => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
    ]
);

// We want to sign the following claims
$claims = [
    'nbf'     => time(),        // Not before
    'iat'     => time(),        // Issued at
    'exp'     => time() + 3600, // Expires at
    'iss'     => 'Me',          // Issuer
    'aud'     => 'You',         // Audience
    'sub'     => 'My friend',   // Subject
    'is_root' => true           // Custom claim
];

// We have to create a JWS class using the JWSFactory.
// The payload of this object contains our claims.
$jws = JWSFactory::createJWS($claims);
// Note that if you want to create a JWS with a detached payload, you just have to set the second parameter as true.
// $jws = JWSFactory::createJWS($claims, true);

// We add information to create the first signature
$jws = $jws->addSignatureInformation(
    key1,
    [
        'alg' => 'RS256',
    ]
);

// Then the information for the second signature
$jws = $jws->addSignatureInformation(
    key2,
    [
        'alg' => 'HS512',
    ]
);
```

Now, the variable `$jws` contains an object that implements `Jose\Object\JWSInterface` and contain information to create two signatures.
It is important to note that the signature have not been calculated at this moment.

We need to create a `Signer` object that will done this step.

```php
use Jose\Signer;

// We create a Signer object with the signature algorithms we want to use
$signer = Signer::createSigner(['RS256', 'HS512']);

// Then we sign
$signer->sign($jws);
```

Now you can export it into the JSON General Serialization Mode:

```php
$jws->toJSON();
```

You can also get each signature into Compact or Flattened Serialization Mode:

```php
// The first signature into Compact Serialization Mode
$jws->toCompactJSON(0);

// The second one into Flattened Serialization Mode
$jws->toFlattenedJSON(1);
```

## Dealing with Unencoded Payload

This library supports unencoded payload (see [RFC7797](https://tools.ietf.org/html/rfc7797)).
You will be able to create JWS with such payload.

```php
use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;

// We load our key (JWK). It is an encrypted RSA key stored in a file
// Additional parameters ('kid', 'alg' and 'use') are set for this key (not mandatory but recommended).
$key = JWKFactory::createFromKeyFile(
    '/Path/To/My/RSA/private.encrypted.key',
    'Password',
    [
        'kid' => 'My Private RSA key',
        'alg' => 'RS256',
        'use' => 'sig',
    ]
);

// We want to sign the following claims
$claims = [
    'nbf'     => time(),        // Not before
    'iat'     => time(),        // Issued at
    'exp'     => time() + 3600, // Expires at
    'iss'     => 'Me',          // Issuer
    'aud'     => 'You',         // Audience
    'sub'     => 'My friend',   // Subject
    'is_root' => true           // Custom claim
];

$jws = JWSFactory::createJWSToFlattenedJSON(
    $claims,                      // The payload or claims to sign
    $key,                         // The key used to sign
    [                             // Protected headers. Muse contains at least the algorithm
        'b64'  => false,                 // We indicates the payload must not be encoded
        'crit' => ['exp', 'aud', 'b64'], // When 'b64' header is used, the 'crit' header must contain the 'b64' value
        'alg'  => 'RS256',
    ]
);
```

**Please note that you can create a JWS in compact JSON when payload is not encoded only if the payload is detached.**

```php
// Will throw an exception
jws = JWSFactory::createJWSToCompactJSON(...);

// Will return the expected JWS in compact JSON
jws = JWSFactory::createJWSWithDetachedPayloadToCompactJSON(...);
```
