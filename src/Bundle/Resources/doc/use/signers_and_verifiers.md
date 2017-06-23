Signers and Verifiers Services
==============================

# Signers

```php
use Jose\Factory\JWSFactory;

// We get the key and the signer (we suppose that MY_KEY1 is a valid key)
$key = $container->get('jose.key.MY_KEY1');
$signer = $container->get('jose.signer.SIGNER1'); // Only if the service is public

// The payload to sign
$payload = 'Hello World!';

// We create a JWS object
$jws = JWSFactory::createJWS($payload);

// We set the information for the signature
$jws->addSignatureInformation(
    $key,
    [
        'alg' => 'HS512',
    ]
);

// We sign it
$signer->sign($jws);

//We can get the Compact, Flattened or General Serialization Representation of that JWS
// 0 is the signature index (the first signature in this case)
$jws->toCompactJSON(0);
$jws->toFlattenedJSON(0);
$jws->toJSON();
```

# Verifiers

```php
// The JWS
$input = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0';

// We get the key and the verifier (we suppose that MY_KEY1 is a valid key)
$key = $container->get('jose.key.MY_KEY1');
$verifier = $container->get('jose.signer.VERFIER1'); // Only if the service is public

// We load the input.
$loader = $this->getContainer()->get('jose.loader');
$jws = $loader->load($input);
// The variable $jws is now a JWSInterface object.
// It could be a JWEInterface object. Please check it before continuing.

// We verify the signature with our key.
// The third argument is the detached payload. In that case the payload is not detached and null is passed as argument value.
// The fourth argument will be populate if the signature verification succeeded. The value corresponds to the verified signature index.
// The value 0 (zero) is a valid value!
$verifier->verifyWithKey($jws $key, null, $index);
```

If you have multiple keys, you can group them in a JWKSet to verify the JWS object:

```php
...
$key_set = $container->get('jose.key_set.MY_KEYSET');
$verifier->verifyWithKeySet($jws $key_set, null, $index);
```
