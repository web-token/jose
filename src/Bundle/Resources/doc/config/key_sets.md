Key Sets
========

# From a List of Keys

The following example shows you how to load a key set from a list of keys.

```yml
jose:
    key_sets:
        keyset_id: # ID of the key set. When loaded, the service "jose.key_set.keyset_id" will be created
            keys: # Type of key set. In this case, the key set is created using keys previously loaded.
                id:
                    - 'jose.key.key_id1'
                    - 'jose.key.key_id2'
                    - 'jose.key.key_id3'
```

# From a JWKSet

The following example shows you how to load a key set from a serialized JWKSet.

```yml
jose:
    key_sets:
        keyset_id: # ID of the key set. When loaded, the service "jose.key_set.keyset_id" will be created
            jwkset: # Type of key set. In this case, the key set is created from a serialized JWKSet.
                value: '{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sign","key_ops":["sign"],"alg":"ES256","kid":"0123456789"},{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI","use":"sign","key_ops":["verify"],"alg":"ES256","kid":"9876543210"}]}'
```

# From a JKU (JSON Wek Key URL)

The following example shows you how to load a key set from an URL that contains keys serialized into JWKSet.

```yml
jose:
    key_sets:
        keyset_id: # ID of the key set. When loaded, the service "jose.key_set.keyset_id" will be created
            jku: # Type of key set. In this case, the key set is created from a serialized JWK.
                url: "https://www.googleapis.com/oauth2/v2/certs"
                is_secured: true # If false, unsecured connections are allowed. Default is true
                cache: 'cache.app' # PSR-6: Caching Interface service. See http://www.php-fig.org/psr/psr-6/ and http://symfony.com/blog/new-in-symfony-3-1-cache-component
                cache_ttl: 300 # Lifetime in seconds of the cache (default is 86400 = 24 hrs)
```

# From a X5U (X509 Certificates URL)

The following example shows you how to load a key set from an URL that contains certificates.

```yml
jose:
    key_sets:
        keyset_id: # ID of the key set. When loaded, the service "jose.key_set.keyset_id" will be created
            x5u: # Type of key set. In this case, the key set is created from a serialized JWK.
                url: "https://www.googleapis.com/oauth2/v1/certs"
                is_secured: true # If false, unsecured connections are allowed. Default is true
                cache: 'cache.app' # PSR-6: Caching Interface service. See http://www.php-fig.org/psr/psr-6/ and http://symfony.com/blog/new-in-symfony-3-1-cache-component
                cache_ttl: 300 # Lifetime in seconds of the cache (default is 86400 = 24 hrs)
```

# Random Key Set

The following example shows you how to create a Key Set with random keys.
This key set is stored so that you can reuse it.

All types of keys are supported, however it can only contains one type of keys.

```yml
jose:
    key_sets:
        keyset_id: # ID of the key set. When loaded, the service "jose.key_set.keyset_id" will be created
            auto: # Type of key set. In this case, the key set is created using random keys
                storage_path: "%kernel.cache_dir%/auto_encryption.keyset" # The file where the key set is stored
                is_rotatable: true # If true, then the key set can rotate its keys after a period of time
                nb_keys: 2 # Number of keys in the key set
                key_configuration: # Key configuration parameters. See the documentation for the random keys for more information.
                    kty: 'EC' # Type of the key. Supported types are RSA, EC, oct, none and OKP (if third party libraries are installed)
                    crv: 'P-521' # Parameters specific to the key type
                    alg: "ECDH-ES"
                    use: "enc"
```

Please read [this page](../use/commands.md) to know how to use console commands with this kind of key set.

# Key Set of Key Sets

In some context you may need to get a key set that contains several key sets.
For example you want to merge your signature an encryption keys.

```yml
jose:
    key_sets:
        keyset_id: # ID of the key set. When loaded, the service "jose.key_set.keyset_id" will be created
            jwksets: # Type of key set. In this case, the key set is created using key sets
                id: 
                    - 'jose.key_set.signature_keys'
                    - 'jose.key_set.encryption_keys'
```

# Public Keys of a Key Set

In some context you may need to share your public keys with third party applications.
To avoid mistakes and to be sure that no private or symmetric keys are shared, you may need that kind od key set.

```yml
jose:
    key_sets:
        keyset_id: # ID of the key set. When loaded, the service "jose.key_set.keyset_id" will be created
            public_jwkset: # Type of key set. In this case, the key set is created using another key set and will show only public keys
                id:  'jose.key_set.signature_keys'
```

# Key Sets Combinations

The following example will show you how to combine random key sets to share signature and encryption public keys at once.

```yml
jose:
    key_sets:
        signature_keys: # Our signature keys
            auto:
                storage_path: "%kernel.cache_dir%/signature_keys.keyset"
                is_rotatable: true
                nb_keys: 2
                key_configuration:
                    kty: 'RSA'
                    size: 4096
                    alg: "RS256"
                    use: "sig"
        encryption_keys: # Our encryption keys
            auto:
                storage_path: "%kernel.cache_dir%/encryption_keys.keyset"
                is_rotatable: true
                nb_keys: 2
                key_configuration:
                    kty: 'EC'
                    crv: 'P-521'
                    alg: "ECDH-ES"
                    use: "enc"
        all_in_one:
            jwksets: # Combine our signature and encryption keys
                id:
                    - 'jose.key_set.signature_keys'
                    - 'jose.key_set.encryption_keys'
        all_in_one_public: # Allow use to share all public keys at once
            public_jwkset:
                id: 'jose.key_set.all_in_one'
```

Now the service `jose.key_set.all_in_one_public` will contain all public keys and can be shared with third party applications.

# Share a JWKSet

As explained above, in some context it is interesting to share public keys.

That is why this bundle provides an easy way to share any JWKSet through a route and a controller.
And because you should not loose time to create controllers and routes, this bundle provides all the features built-in.

The way it is managed is quite simple:

## Add The Built-in Route File

Just add the following lines into your routing file:

```yml
# routing.yml
jwkset_endpoint:
    resource: "@SpomkyLabsJoseBundle/Resources/config/routing/jwkset_controller.yml"
    prefix: '/keys' # You can prefix it as any other route
```

## Share Yyour JWKSet

There is nothing to do except adding a `path` parameter for each key set you wamt to share.
This path should be something like `/path/to/the/key/set`.

Each path must be unique otherwise previous routes will be erased.

```yml
jose:
    key_sets:
        ...
        all_in_one_public:
            public_jwkset:
                path: '/public_keys' # Note we set a path
                id: 'jose.key_set.all_in_one'
```

## Access On Your JWKSet

The complete URL of your key set is `HOST + PREFIX + PATH [+ FORMAT]` and the route name is `jwkset_KEY_ID`.

In our example and for the `all_in_one_public` key set, if the host is `http://www.example.com`, the complete URL is `http://www.example.com/keys/public_keys`
and the route name is `jwkset_all_in_one_public`.

### JWKSet Format

The associated controller is able to return the key set in two different formats: `JSON` and `PEM`. By default the format is `JSON`.

Example:

- At `http://www.example.com/keys/public_keys` you will get the key set into JSON. The content type is `application/jwkset+json`.
- At `http://www.example.com/keys/public_keys.json` you will get the key set into JSON. The content type is `application/jwkset+json`.
- At `http://www.example.com/keys/public_keys.pem` you will get the key set into PEM. The content type is `application/json`.
