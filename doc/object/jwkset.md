The JWKSet object
=================

# Overview

The JWKSet object represents a key set and is able to store multiple keys.
The class `Jose\Object\JWKSet` implements the interface `Jose\Object\JWKSetInterface` and provides the following methods:
* `getKey($index)`: get the key at index `$index`
* `getKeys()`: get all keys
* `addKey(JWKInterface $key)`: add a key
* `removeKey($key)`: remove a key at index `$index`

Note that a JWKSet object
* is countable: you can call method `count()`,
* is traversable: you can use a JWK as `foreach` argument
* is serializable: You can call `json_encode($jwkset)` to display the key set as a string (e.g. `{'keys':[{'kty':'oct', 'k':'abcdef...'}]}`). Such string is mainly used to share public keys through an URL.
* can be used like an array
    * `$jwkset[] = $jwk;`: Add a new key in the key set
    * `$jwkset[$index];`: Return the key at the index `$index`. `$index` must be an integer.
    * `unset($jwkset[$index]);`: Remove the key at the index `$index`

Example:

```php
use Jose\Object\JWKSet;

$jwkset = new JWKSet();

$jwkset->addKey($key1); // or $jwkset[] = $key1;
print_r(json_encode($jwkset)); // {'keys':[{'kty':'oct', 'k':'abcdef...'}]}
```

# Key Factory

Your key sets may be stored in a json encoded string or are available through an URL.
You can easily load and create key sets from several sources using the `Jose\Factory\JWKFactory` factory provided with this library.

## Create a Key from values

```php
use Jose\Factory\JWKFactory;

$jwk_set = JWKFactory::createFromValues(['keys' => [
    [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
        'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
    ],
    [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
        'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
    ],
]);
```

Please note that the above method will give the same result as the following one.
The only difference is that the first method uses a static call on the factory instead of creating an object through a new instance.
We recommend you to use the first method.

```php
use Jose\Object\JWKSet;

$jwk_set = new JWKSet(['keys' => [
    [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x'   => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
        'y'   => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
        'd'   => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
    ],
    [
        'kty' => 'EC',
        'crv' => 'P-256',
        'x'   => 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
        'y'   => 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
        'd'   => '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
    ],
]);
```

## Create a Key from a JWKSet Url (`jku`)

This method will try to load keys from an Url.
The Url must contain a valid JWKSet.

The following example will try to load Google public keys:

```php
use Jose\Factory\JWKFactory;

$jwk_set = JWKFactory::createFromJKU('https://www.googleapis.com/oauth2/v2/certs');
```

### Unsecured Connections

The URL to get the JWKSet is supposed to be secured as per the specification.
However, you may need to retrieve your JWKSet through an unsecured connection (e.g. during tests).

Unsecured connections are:
- Connections with the `http` scheme
- Connection to a server that provides self-signed certificates or invalid certificates.

The method `createFromJKU` allows unsecured connection. Just set the second as `true`:

```php
use Jose\Factory\JWKFactory;

$jwk_set = JWKFactory::createFromJKU('http://www.example.com/certs', true);
```

### Caching Support

To avoid calls to a server each time you need a certificate, the `createFromJKU` supports [PSR-6: Caching Interface](http://www.php-fig.org/psr/psr-6/) compatible cache item pools.

```php
use Jose\Factory\JWKFactory;

$cacheItemPool = YourValidCacheItemPool //An instance of a class that implements Psr\Cache\CacheItemPoolInterface
$ttl = 300; //Cache lifetime in seconds. Default is 86400 = 24 hrs. 0 means the cache never expires (not recommended).

$jwk_set = JWKFactory::createFromJKU('http://www.example.com/certs', false, $cacheItemPool, $ttl);
```

### HTTP Connection Support

During tests for example, it is useful to retrieve keys using a non-encrypted connection (HTTP).
From the version 6.1 of this library, it is possible to allow URLs with the `http://` scheme.

You just have to set the last argument as `true`.

```php
use Jose\Factory\JWKFactory;

$jwk_set = JWKFactory::createFromJKU('http://www.example.com/certs', false, null, 0, true);
```


## Create a Key from a X509 Certificate Url (`x5u`)

This method will try to load keys from an Url.
The Url must contain a valid X509 certificate list.

The following example will try to load Google public keys:

```php
use Jose\Factory\JWKFactory;

$jwk_set = JWKFactory::createFromX5U('https://www.googleapis.com/oauth2/v1/certs');
```

### Unsecured, HTTP Connections and Caching Support

The method `createFromX5U` supports the same arguments as the method `createFromJKU` for unsecured, HTTP connections or caching support.

## Create a Key Set with Random keys

You may need to create and store a key set with random keys.
This library provides an easy way to create such key set by using the `createStorableKeySet` method.

```php
use Jose\Factory\JWKFactory;

$rotatable_key_set = JWKFactory::createStorableKeySet(
    '/path/to/the/storage/file.keyset', // The file which will contain the key set
    [
        'kty' => 'OKP',
        'crv' => 'X25519',
        'alg' => 'ECDH-ES',
        'use' => 'enc',
    ],
    3,                      // Number of keys in that key set
);
```

### Random Key Configurations

The random keys created with that JWKSet are all of the same type. The configuration of those keys depends on their type and is similar to the configuration of [a random key](https://github.com/Spomky-Labs/jose/blob/master/doc/object/jwk.md#create-a-random-key).
The main difference is that you do not have to define a `kid` as it is automatically generated.

Additional paramters are accepted and are set for all key within the key set.

#### Create a Random `oct` Key Set

The following example will create `oct` keys.
The key size is 256 bits (`'size' => 256`) and that key will be used with the `HS256` algorithm for signature/verification only.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createStorableKeySet(
    '/path/to/the/storage/file.keyset', // The file which will contain the key set
    [
        'kty'  => 'oct',
        'size' => 256,
        'alg'  => 'HS256',
        'use'  => 'sig',
        'foo'  => 'bar',
    ],
    3,                      // Number of keys in that key set
);
```

#### Create a Random `RSA` Key Set

The following example will create `RSA` keys.
The key size is 4096 bits and that key will be used with the `RSA-OAEP` algorithm for encryption/decryption only.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createStorableKeySet(
    '/path/to/the/storage/file.keyset', // The file which will contain the key set
    [
        'kty'  => 'RSA',
        'size' => 4096,
        'alg'  => 'RSA-OAEP',
        'use'  => 'enc',
    ],
    3,                      // Number of keys in that key set
);
```

#### Create a Random `EC` Key Set

The following example will create `EC` keys.
The key uses the `P-521` curve and will be used with the `ES512` algorithm for signature/verification only.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createStorableKeySet(
    '/path/to/the/storage/file.keyset', // The file which will contain the key set
    [
        'kty' => 'EC',
        'crv' => 'P-521',
        'alg' => 'ES512',
        'use' => 'sig',
    ],
    3,                      // Number of keys in that key set
);
```

#### Create a Random `OKP` Key Set

The following example will create `OKP` keys.
The key uses the `X25519` curve and will be used with the `ECDH-ES` algorithm for encryption/decryption only.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createStorableKeySet(
    '/path/to/the/storage/file.keyset', // The file which will contain the key set
    [
        'kty' => 'OKP',
        'crv' => 'X25519',
        'alg' => 'ECDH-ES',
        'use' => 'enc',
    ],
    3,                      // Number of keys in that key set
);
```

#### Create a Random `None` Key Set

This configuration is absolutely useless as it is not relevant to use 3 "random" `none` keys.
However this configuration is possible.

```php
use Jose\Factory\JWKFactory;

$jwk = JWKFactory::createStorableKeySet(
    '/path/to/the/storage/file.keyset', // The file which will contain the key set
    [
        'kty' => 'none',
    ],
    3,                      // Number of keys in that key set
);
```

## Create a Rotatable Key Set

Some applications may require a key set with keys that are updated after a period of time.
To continue to validate JWS or decrypt JWE, the old keys should be able for another period of time.

That is the purpose of the Rotatable Key Set.
This kind of key set is configured exactly like a random key set.

Those JWKSets implement the `Jose\Object\RotatableInterface` and the method `rotate`.

You can manipulate that key set as any other key sets, however you cannot add or remove keys.

We recommend you to use the first key of that key set to perform your signature/encryption operations.

Except when the key set is created, all keys will be available at least during `number of key * period of time`.

```php
use Jose\Factory\JWKFactory;

$rotatable_key_set = JWKFactory::createRotatableKeySet(
    '/path/to/the/storage/file.keyset', // The file which will contain the key set
    [
        'kty' => 'OKP',
        'crv' => 'X25519',
        'alg' => 'ECDH-ES',
        'use' => 'enc',
    ],
    3,                      // Number of keys in that key set
    3600                    // This key set will rotate all keys after 3600 seconds (1 hour)
);
```

## Key Set of Key Sets

In some cases you may need to merge key sets and use it as a unique key set.
Then the `JWKSets` class is made for you.

```php
use Jose\Factory\JWKFactory;

$key_sets = JWKFactory::createKeySets([
    $jwkset1,
    $jwkset2,
    $jwkset3,
    ...
]);
```

## Public Keys Only

In some cases you may need to share public keys with third parties.
This library provides a JWKSet that returns only public keys.

It is compatible with the any JWKSet, including `JWKSets` or `RotatableJWKSet` classes.

```php
use Jose\Factory\JWKFactory;

$public_key_set = JWKFactory::createPublicKeySet($jwkset);
```

## Key Sets Chaining

Let say you have two rotatable key sets: one for signature and the other one for encryption purpose.
You want to share the public keys with third parties by providing a unique URL where all public keys can be retrieved.

Then you can merge your rotatable key sets and use that JWKSet to share public keys.

```php
use Jose\Factory\JWKFactory;

$signing_keys = JWKFactory::createRotatableKeySet(
    '/path/to/the/storage/signature.keyset',
    [
        'kty'  => 'RSA',
        'size' => 4096,
        'alg'  => 'RS512',
        'use'  => 'sig',
    ],
    3,
    3600
);

$encryption_keys = JWKFactory::createRotatableKeySet(
    '/path/to/the/storage/encryption.keyset',
    [
        'kty' => 'OKP',
        'crv' => 'X25519',
        'alg' => 'ECDH-ES',
        'use' => 'enc',
    ],
    3,
    3600
);

$jwkset = JWKFactory::createKeySets([
    $signing_keys,
    $encryption_keys,
]);
$public_key_set = JWKFactory::createPublicKeySet($jwkset);
```

Now you cqn use the first key of the `$signing_keys` and `$encryption_keys` for all your operations and share the `$public_key_set` with third parties.

# Key Selection

JWKSet object can contain several keys. To easily find a key according to constraint, a method `selectKey` is available.

```php
// Find a key used to encrypt/decrypt
$jwk_set->selectKey('enc');

// Find a key used to sign/verify
$jwk_set->selectKey('sig');

// Find a key used to sign/verify using the algorithm 'RS256'
$jwk_set->selectKey('sig', 'RS256');

// Find a key used to encrypt/decrypt with kid = '0123456789'
$jwk_set->selectKey('enc', null, ['kid'=>'0123456789']);

// Find a key used to sign/verify with sha256 thumbprint = '0123456789'
$jwk_set->selectKey('sig', null, ['x5t#256'=>'0123456789']);
```

We recommend you to always define the following key/value pairs for each key:

* `kid`: the ID of the key
* `use`: the usage of the key (`sig` for signature or `enc` for encryption operations)
* `alg`: the algorithm allowed for this key

The selection of the best key to use will be more efficient.
