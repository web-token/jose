Create and Load a signed token using the bundles
================================================

The creation and the loading of a signed token is very easy using the Symfony bundles.

First, you have to ensure that the following bundles are enabled:

* `Jose\Bundle\Framework\FrameworkBundle`
* `Jose\Bundle\Checker\CheckerBundle`
* `Jose\Bundle\Signature\SignatureBundle`

You should also have a key suitable for the algorithm you intent to use (see [this example](jwk.md) for more information).

# JWS Creation

To create a JWS, we will need a `JWSBuilder` service. Such service can be created using 2 different ways.

## Configuration

The easiest way is to add configuration sections into your `config.yml` file.

With the folloging configuration, we will create a service named `jose.jws_builder.builder1`.
The builder will only support the `ES256` signature algorithm.

```yaml
#app/config.yml

jose:
    jws_builders:
        builder1:
            is_public: true
            signature_algorithms: ['ES256']
```

## Bundle Extension

This framework provides an helper that will help you to dynamically create services for you.

To do so, your Extension file into the `DependencyInjection` folder must extend the `PrependExtensionInterface` interface.
Then, just call the `ConfigurationHelper::addJWSBuilder` method to add your new builder.

```php
<?php

declare(strict_types=1);

namespace AcmeBundle\DependencyInjection;

use Jose\Bundle\JoseFramework\Helper\ConfigurationHelper;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

final class AcmeExtension extends Extension implements PrependExtensionInterface
{
    ...
    
    /**
     * {@inheritdoc}
     */
    public function prepend(ContainerBuilder $container)
    {
        ConfigurationHelper::addJWSBuilder($container, 'builder1', ['ES256'], true);
    }
}
```

## Create A Signed Token

```php
<?php

declare(strict_types=1);

final class MyService
{
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

    // We suppose here that you can get access to the container
    $jws = $this->getContainer->get('jose.jws_builder.builder1');
        ->withPayload($payload)        // We set our payload
        ->addSignature($jwk, $headers) // We want only one signature with our key and header
        ->build();                     // We build the JWS object

    // The token will be serialized into a compact token
    $serializer = $this->getContainer->get(CompactSerializer::class);

    // We serialize the JWS into a compact token.
    // The second argument refers to the index of the signature to serialize (0 = the first one).
    $token = $serializer->serialize($jws, 0);

    // The variable $token now contains our token.
    // It should look like eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJNeSBzZXJ2aWNlIiwiZXhwIjoxNTA2MjYzNDQwLCJpYXQiOjE1MDYyNTk4NDAsIm5iZiI6MTUwNjI1OTg0MH0.cvk1xdLmIdIGtSNsikRhyxAVOkPNP7DSCXQVZQUP-ua_feow1ddQByxCc7uKm3-FQJ4pIvKkYGX25Nl5kXiouw
}
```

