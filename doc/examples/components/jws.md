Create and Load a signed token using the components
===================================================

With the following example, you will understand how to create a signed token and how to load it.

# JWS Creation

```php
<?php

declare(strict_types=1);

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardJsonConverter;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

// The algorithm we will use is ES256
$algorithManager = AlgorithmManager::create([
    new ES256(),
]);

// The key we will use.
$jwk = JWKFactory::createECKey('P-256', [
    'kid' => 'My Key',
    'use' => 'sig',
    'alg' => 'ES256',
]);

// We store our private key in a file. We will use it again for the token verification
file_put_contents('/tmp/secret.key', json_encode($jwk), LOCK_EX);

// The JSON Converter. We use the default configuration.
$jsonConverter = new StandardJsonConverter();

$jwsBuilder = new JWSBuilder(
    $jsonConverter,
    $algorithManager
);

// The payload we want to sign
$payload = [
    'iss' => 'My service',
    'exp' => time()+3600,
    'iat' => time(),
    'nbf' => time(),
];

// The header. Nothing but the algorithm we use.
$headers = [
    'alg' => 'ES256',
];

$jws = $jwsBuilder
    ->withPayload($payload)        // We set our payload
    ->addSignature($jwk, $headers) // We want only one signature with our key and header
    ->build();                     // We build the JWS object

// The token will be serialized into a compact token
$serializer = new CompactSerializer();

// We serialize the JWS into a compact token.
// The second argument refers to the index of the signature to serialize (0 = the first one).
$token = $serializer->serialize($jws, 0);

// The variable $token now contains our token.
// It should look like eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2aWNlIiwiZXhwIjoxNTA2MjYzNDQwLCJpYXQiOjE1MDYyNTk4NDAsIm5iZiI6MTUwNjI1OTg0MH0.cvk1xdLmIdIGtSNsikRhyxAVOkPNP7DSCXQVZQUP-ua_feow1ddQByxCc7uKm3-FQJ4pIvKkYGX25Nl5kXiouw
```

# JWS Loading

We will now load a token. In this example we will use the result of the previous section.

```php
<?php

declare(strict_types=1);

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Converter\StandardJsonConverter;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer;

// The algorithm manager.
$algorithManager = AlgorithmManager::create([
    new ES256(),
]);

// We read our key from the file
$file = file_get_contents('/tmp/secret.key');

// If something when wrong, stop.
if (false === $file) {
    throw new \RuntimeException('Unable to load the key.');
}

// We create our key from the JSON data.
$jwk = JWK::create(json_decode($file, true));

// We convert our private key into a public one.
$jwk = $jwk->toPublic();

// The JSON Converter. We use the default configuration.
$jsonConverter = new StandardJsonConverter();

// We will need to check the "alg" header.
$headerCheckerManager = HeaderCheckerManager::create([
    new AlgorithmChecker(['ES256']),
]);

// We will need to check the "alg" header.
$claimCheckerManager = new ClaimCheckerManager($jsonConverter, [
    new IssuedAtChecker(),
    new ExpirationTimeChecker(),
    new NotBeforeChecker(),
    // As we use the "iss" claim, we should also create a claim checker and use it here.
]);

// The serializer manager. We only support compact serialization in this example.
// If you want to support other serialization modes, just add the serializers in the list.
$serializerManager = JWSSerializerManager::create([
    new CompactSerializer(),
]);

// We create our JWS Loader
$jwsLoader = new JWSLoader(
    $algorithManager,
    $headerCheckerManager,
    $serializerManager
);

// The input to load
$input = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2aWNlIiwiZXhwIjoxNTA2MjYzNDQwLCJpYXQiOjE1MDYyNTk4NDAsIm5iZiI6MTUwNjI1OTg0MH0.cvk1xdLmIdIGtSNsikRhyxAVOkPNP7DSCXQVZQUP-ua_feow1ddQByxCc7uKm3-FQJ4pIvKkYGX25Nl5kXiouw';

// We load the input.
// Nothing is checked here.
$jws = $jwsLoader->load($input);

// We check the JWS using our key (public key).
// If everything is OK, the method returns the index of the signature that has been checked.
$index = $jwsLoader->verifyWithKey($jws, $jwk);

// We can now check the claims
$claimCheckerManager->check($jws);

// If you are here, this means the token you received is verified and can be used by your application.
// Be carefull: the payload is a string. If you want to retrieve your claims as an array, you have to use the following method:
$claims = $jsonConverter->decode($jws->getPayload());
var_dump($claims);
```
