Encrypters and Decrypters Services
==================================

# Encrypters

```php
use Jose\Factory\JWEFactory;

// We get the key of the recipient (we suppose that MY_KEY1 is a valid key)
$key = $container->get('jose.key.MY_KEY1');
$encrypter = $container->get('jose.encrypter.ENCRYPTER1'); // Only if the service is public

// The payload to sign
$payload = 'Hello World!';

// We have to create a JWE class using the JWEFactory.
// The payload of this object contains our message.
$jwe = JWEFactory::createJWE(
    $payload,                 // The payload
    [                         // The shared protected header
        'enc' => 'A128GCM',   // The content encryption algorithm
        'alg' => 'A256GCMKW', // The key encryption algorithm
        'zip' => 'DEF',       // We want to compress the payload before encryption (not mandatory, but useful for a large payload
    ]
);

// We add the recipient public key.
$jwe = $jwe->addRecipientInformation(key1);

// We sign it
$encrypter->encrypt($jwe);

//We can get the Compact, Flattened or General Serialization Representation of that JWE
// 0 is the recipient index (the first recipient in this case)
$jwe->toCompactJSON(0);
$jwe->toFlattenedJSON(0);
$jwe->toJSON();
```

# Decrypters

```php
// The JWE
$input = 'eyJhbGciOiJSU0EtT0FFUCIsImtpZCI6InNhbXdpc2UuZ2FtZ2VlQGhvYmJpdG9uLmV4YW1wbGUiLCJlbmMiOiJBMjU2R0NNIn0.rT99rwrBTbTI7IJM8fU3Eli7226HEB7IchCxNuh7lCiud48LxeolRdtFF4nzQibeYOl5S_PJsAXZwSXtDePz9hk-BbtsTBqC2UsPOdwjC9NhNupNNu9uHIVftDyucvI6hvALeZ6OGnhNV4v1zx2k7O1D89mAzfw-_kT3tkuorpDU-CpBENfIHX1Q58-Aad3FzMuo3Fn9buEP2yXakLXYa15BUXQsupM4A1GD4_H4Bd7V3u9h8Gkg8BpxKdUV9ScfJQTcYm6eJEBz3aSwIaK4T3-dwWpuBOhROQXBosJzS1asnuHtVMt2pKIIfux5BC6huIvmY7kzV7W7aIUrpYm_3H4zYvyMeq5pGqFmW2k8zpO878TRlZx7pZfPYDSXZyS0CfKKkMozT_qiCwZTSz4duYnt8hS4Z9sGthXn9uDqd6wycMagnQfOTs_lycTWmY-aqWVDKhjYNRf03NiwRtb5BE-tOdFwCASQj3uuAgPGrO2AWBe38UjQb0lvXn1SpyvYZ3WFc7WOJYaTa7A8DRn6MC6T-xDmMuxC0G7S2rscw5lQQU06MvZTlFOt0UvfuKBa03cxA_nIBIhLMjY2kOTxQMmpDPTr6Cbo8aKaOnx6ASE5Jx9paBpnNmOOKH35j_QlrQhDWUN6A2Gg8iFayJ69xDEdHAVCGRzN3woEI2ozDRs.-nBoKLH0YkLZPSI9.o4k2cnGN8rSSw3IDo1YuySkqeS_t2m1GXklSgqBdpACm6UJuJowOHC5ytjqYgRL-I-soPlwqMUf4UgRWWeaOGNw6vGW-xyM01lTYxrXfVzIIaRdhYtEMRBvBWbEwP7ua1DRfvaOjgZv6Ifa3brcAM64d8p5lhhNcizPersuhw5f-pGYzseva-TUaL8iWnctc-sSwy7SQmRkfhDjwbz0fz6kFovEgj64X1I5s7E6GLp5fnbYGLa1QUiML7Cc2GxgvI7zqWo0YIEc7aCflLG1-8BboVWFdZKLK9vNoycrYHumwzKluLWEbSVmaPpOslY2n525DxDfWaVFUfKQxMF56vn4B9QMpWAbnypNimbM8zVOw.UCGiqJxhBI3IFVdPalHHvA';

// We get the key and the decrypter (we suppose that MY_KEY1 is a valid key)
$key = $container->get('jose.key.MY_KEY1');
$decrypter = $container->get('jose.signer.DECRYPTER1'); // Only if the service is public

// We load the input.
$loader = $this->getContainer()->get('jose.loader');
$jwe = $loader->load($input);
// The variable $jwe is now a JWEInterface object.
// It could be a JWSInterface object. Please check it before continuing.

// We decrypt the JWE with our key.
// The third argument will be populate if the recipient decyprtion succeeded. The value corresponds to the decrypted recipient index.
// The value 0 (zero) is a valid value!
$decrypter->public function decryptUsingKey($jwe, $key, $index);
```

If you have multiple keys, you can group them in a JWKSet to decrypt the JWE object:

```php
...
$key_set = $container->get('jose.key_set.MY_KEYSET');
$decrypter->decryptUsingKeySet($jwe $key_set, $index);
```
