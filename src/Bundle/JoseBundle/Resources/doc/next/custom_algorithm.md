Custom Algorithm
================

The [spomky-Labs/jose](https://github.com/Spomky-Labs/jose) library already provides dozen of algorithms, but you may need to use your own algorithm.

In the following example, we will create a dummy signature algorithm that produces signature with the `MD5` hash of the input and adds `--SIGNED--` at the end.

# Create it!

Depending on the algorithm, you have to implement one of the following interfaces:

- `Jose\Algorithm\SignatureAlgorithmInterface` for a signature algorithm.
- `Jose\Algorithm\ContentEncryptionAlgorithmInterface` for a content encryption algorithm.
- `Jose\Algorithm\KeyEncryption\DirectEncryptionInterface` for a direct key encryption algorithm (should not be needed).
- `Jose\Algorithm\KeyEncryption\KeyAgreementInterface` for a key agreement algorithm.
- `Jose\Algorithm\KeyEncryption\KeyAgreementWrappingInterface` for a key agreement with key wrapping algorithm.
- `Jose\Algorithm\KeyEncryption\KeyEncryptionInterface` for a key encryption algorithm.
- `Jose\Algorithm\KeyEncryption\KeyWrappingInterface` for a key wrapping algorithm.

In our example, we implement the first one:

```php
<?php

namespace AppBundle\Algorithm;

use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Component\Core\JWK;

final class DummySignatureAlgorithm implements SignatureAlgorithmInterface
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmName()
    {
         return 'Dummy'; // The name of our algorithm
    }
    
    /**
     * {@inheritdoc}
     */
    public function sign(JWK $key, $input)
    {
        // Note that the key is not used in this example.
        // A real example should use it.
        return $this->computeSignature($input); // We compute the signature
    }
    
    /**
     * {@inheritdoc}
     */
    public function verify(JWK $key, $input, $signature)
    {
        // We compare the signature and the computed one
        return hash_equals($signature, $this->computeSignature($input));
    }
    
    /**
     * @return string
     */
    private function computeSignature($input)
    {
        // Our signature is just a MD5 of the input + --SIGNED--
        return sprintf('%s --SIGNED--', hash('md5', $input));
    }
}
```

# Add it!

Now we have a new algorithm, we have to create a tagged service that will be added to the algorithm manager algorithm list.

```xml
<?xml version="1.0" ?>

<container xmlns="http://symfony.com/schema/dic/services"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://symfony.com/schema/dic/services http://symfony.com/schema/dic/services/services-1.0.xsd">

    <services>
        <service id="app.algorithm.dummy" class="AppBundle\Algorithm\DummySignatureAlgorithm" public="false">
            <tag name="jose.algorithm" />
        </service>
    </services>
</container>
```

# Use it!

Now we can produce JWT using our custom algorithm:

```yml
jose:
    easy_jwt_creator:
        custom: # We create a JWT Creator service that supports our custom algorithm
            is_public: true
            signature_algorithms:
                - 'Dummy' # The algorithm name is the same the one one returned by the method getAlgorithmName()
```

```php
<?php

// We suppose the key is a valid key
$jwt = $container->get('jose.jwt_creator.custom')->createJWSToCompactJSON('Hello', ['alg' => 'Dummy']);
```

The jwt should look like `eyJhbGciOiJEdW1teSJ9.SGVsbG8.MTg2ZjZjMTY3MWYyMWMzMzFhODE5ZjAxOGIyNGYxNGIgLS1TSUdORUQtLQ`. The last part is the `186f6c1671f21c331a819f018b24f14b --SIGNED--` encoded in Base64 Url Safe
which corresponds to the computed signature.
