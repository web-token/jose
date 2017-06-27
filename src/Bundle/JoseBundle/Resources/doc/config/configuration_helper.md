# Bundle Integration

This bundle may be used by other bundles to provide JWT support.
If your are in that case, then you will have to configure your bundle and the JoseBundle and your configuration file will become too verbose.

That is why this bundle provides a [`ConfigurationHelper`](../../Helper/ConfigurationHelper.php) that will help your to modify the configuration of JoseBundle from your bundle.

Let say you have a bundle that need a key set, a decrypter, a verfier and a claim checker to load and verify encrypted JWS.
Your public keys are share to allow third party applications to send you those JWT.

Normally your configuration file should be something like that one:

```yml
...
# The JoseBundle configuration
jose:
    easy_jwt_loader:
        main:
            signature_algorithms:
                - 'RS256'
            key_encryption_algorithms:
                - 'RSA-OAEP-256'
            content_encryption_algorithms:
                - 'A256GCM'
            claim_checkers:
                - 'exp'
                - 'iat'
                - 'nbf'
            header_checkers:
                - 'crit'
    key_sets:
        signature_keys:
            auto:
                storage_path: "%kernel.cache_dir%/signature_keys.keyset"
                is_rotatable: true
                nb_keys: 2
                key_configuration:
                    kty: 'RSA'
                    size: 4096
                    alg: "RS256"
                    use: "sig"
        encryption_keys:
            auto:
                storage_path: "%kernel.cache_dir%/encryption_keys.keyset"
                is_rotatable: true
                nb_keys: 2
                key_configuration:
                    kty: 'RSA'
                    size: 4096
                    alg: "RSA-OAEP-256"
                    use: "enc"
        all_keys:
            jwksets:
                id:
                    - 'jose.key_set.signature_keys'
                    - 'jose.key_set.encryption_keys'
        all_public_keys:
            public_jwkset:
                id: 'jose.key_set.all_keys'
```

As you can see the configuration file is too heavy for the job to do.
Let's shrink all to lines.

## Update your Bundle Extension

To allow your bundle to get the advantages of the Configuration Helper, you have to implement the `Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface` in your bundle extension class.

```php
<?php

namespace AppBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class AppExtension extends Extension implements PrependExtensionInterface
{
    public function prepend(ContainerBuilder $container)
    {
        ...
    }
}
```

Then, in the `prepend` method, you can add any services you want. Their order is not important, but we recommend you to add them in this order:
- Keys
- Key Sets
- Checkers
- Signers
- Verifiers
- Encrypters
- Decrypters
- JWT Loaders
- JWT Creators

**Please note that all services cannot be set using the configuration helper.**

## Add Your Key Sets

```php
use SpomkyLabs\JoseBundle\Helper\ConfigurationHelper;

...
public function prepend(ContainerBuilder $container)
{
    //We add our signature keys
    ConfigurationHelper::addRandomJWKSet(
        $container,
        'signature_keys', // Key Set ID
        '%kernel.cache_dir%/signature_keys.keyset', // Storage path
        2, // Number of keys
        [ // Key configuration
            'kty'  => 'RSA',
            'size' => 4096,
            'alg'  => "RS256",
            'use'  => "sig",
        ],
        true, // Is rotatable?
        true // Is public?
    );
    
    //We add our encryption keys
    ConfigurationHelper::addRandomJWKSet($container, 'encryption_keys', '%kernel.cache_dir%/encryption_keys.keyset', 2, ['kty'  => 'RSA', 'size' => 4096, 'alg'  => "RSA-OAEP-256", 'use'  => "enc"], true, true);
    
    //And then we merge our key sets and get a public key set
    ConfigurationHelper::addJWKSets($container, 'all_keys', ['jose.key_set.signature_keys', 'jose.key_set.encryption_keys']);
    ConfigurationHelper::addPublicJWKSet($container, 'all_public_keys', 'jose.key_set.all_keys');
}
```

## Checker, Verifier and JWT Loader

The `easy_jwt_loader` configuration parameter is not available using the Configuration Helper.
We have to create services for the checker, the verifier and then the JWT Loader

```php
use SpomkyLabs\JoseBundle\Helper\ConfigurationHelper;

...
public function prepend(ContainerBuilder $container)
{
    //We add the checker (last argument set the service as private as we should not use it directly).
    ConfigurationHelper::addChecker($container, 'main', ['crit'], ['exp', 'iat', 'nbf'], false);
    
    //We add our verifier (private)
    ConfigurationHelper::addVerifier($container, 'main', ['RS256'], false);
    
    //We add our decrypter (private)
    ConfigurationHelper::addDecrypter($container, 'main', ['RSA-OAEP-256'], ['A256GCM'], ['DEF'], false);
    
    //And then we can create our JWT Loader using all previously defined services.
    //The loader is public as we could need it in our controller for example
    ConfigurationHelper::addJWTLoader($container, 'main', 'jose.verifier.main', 'jose.checker.main', 'jose.decrypter.main');
}
```

# Conclusion

When it is possible, use the Configuration Helper as often as possible. The complete `prepend` method looks like:

```php
public function prepend(ContainerBuilder $container)
{
    ConfigurationHelper::addRandomJWKSet($container, 'signature_keys', '%kernel.cache_dir%/signature_keys.keyset', 2, ['kty'  => 'RSA', 'size' => 4096, 'alg'  => "RS256", 'use'  => "sig"], true, true);
    ConfigurationHelper::addRandomJWKSet($container, 'encryption_keys', '%kernel.cache_dir%/encryption_keys.keyset', 2, ['kty'  => 'RSA', 'size' => 4096, 'alg'  => "RSA-OAEP-256", 'use'  => "enc"], true, true);
    ConfigurationHelper::addJWKSets($container, 'all_keys', ['jose.key_set.signature_keys', 'jose.key_set.encryption_keys']);
    ConfigurationHelper::addPublicJWKSet($container, 'all_public_keys', 'jose.key_set.all_keys');
    ConfigurationHelper::addChecker($container, 'main', ['crit'], ['exp', 'iat', 'nbf'], false);
    ConfigurationHelper::addVerifier($container, 'main', ['RS256'], false);
    ConfigurationHelper::addDecrypter($container, 'main', ['RSA-OAEP-256'], ['A256GCM'], ['DEF'], false);
    ConfigurationHelper::addJWTLoader($container, 'main', 'jose.verifier.main', 'jose.checker.main', 'jose.decrypter.main');
}
```

And how the JoseBundle configuration section looks like?

```yml
```

**It's empty!**

Those 10 lines of code are better thant the 40+ configuration lines the user has to set.

As you noted, we use hardcoded values, but you are free to use your own configurable values. In this case, all those values can be options defined in your bundle configuration.
