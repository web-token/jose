How to use
==========

# JWT Creation

## The Easy Way

The example below will show you how to produce JWS or JWE with just few lines.
However, we recommend you to use the JWT Creator

### Create A JWS

```php
// We set our protected header
$protected_header = ['alg' =>'HS512'];

// Our claims
$claims = [
    'iss' => 'My service',
    'aud' => ['Your application'],
    'exp' => 123456,
    'sub' => 'The resource owner',
];

// We get the JWS Factory
$jws_factory = $this->getContainer()->get('jose.factory.jws');

// We retrieve our signature key
$key = $this->getContainer()->get('jose.key.my_signature_key');

// We create our JWS
$jws = $jws_factory->createJWSToCompactJSON($claims, $key, $protected_header);
```

### Create A JWE

```php
// We set our protected header
$shared_protected_header = ['alg' => 'A256GCMKW', 'enc' => 'A256GCM'];

// Our claims
$claims = [
    'iss' => 'My service',
    'aud' => ['Your application'],
    'exp' => 123456,
    'sub' => 'The resource owner',
];

// We get the JWS Factory
$jwe_factory = $this->getContainer()->get('jose.factory.jwe');

// We retrieve our signature key
$key = $this->getContainer()->get('jose.key.my_signature_key');

// We create our JWS
$jwe = $jwe_factory->createJWEToCompactJSON($claims, $key, $shared_protected_header);
```

## The JWT Creator

### Create a JWS

### Create a JWE
