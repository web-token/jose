Keys
====

The following example will show you how to load a key depending on the source of the data.
For all keys, we recommend you to set, besides the required data, additional data such as the key ID (`kid`) and the usage (`use`).

# From Values

With this key type, the JWK is created using values you directly set.

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            values: # Type of key. In this case, we create it using its values
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                values: # The list of values
                    kty: "oct"
                    kid: "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
                    k: "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
```

# From a File

The following example shows you how to load a key stored in a file.

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            file: # Type of key. In this case, the key is stored in an file.
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                path: "/Path/To/The/file.key" # Path of the file
                password: "secret" # If the key is encrypted, this parameter is mandatory
                additional_values: # You can add custom values 
                    kid: "KEY_0123456789"
                    use: 'sig'
```

# From a Certificate

The following example shows you how to load a key from a certificate.

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            certificate: # Type of key. In this case, the key is stored in an certificate.
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                path: "/Path/To/The/certificate.crt" # Path of the certificate
                additional_values: # You can add custom values 
                    kid: "CERT_ABCDE"
                    use: 'sig'
```

# From a JWK

The following example shows you how to load a key from a serialized JWK.

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            jwk: # Type of key. In this case, the key from a serialized JWK.
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                value: '{"kty":"EC","crv":"P-521","d":"Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE","x":"AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS","y":"AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC","foo":"bar"}'
```

# From a JWKSet

The following example shows you how to load a key from a JWKSet.

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            jwkset: # Type of key. In this case, the key from a serialized JWK.
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                id: 'jose.key_set.my_key_set' # The key we want to load is in that JWKSet
                index: 0                      # Index of the key in the JWKSet. The key MUST exist otherwise an exception will be thrown
```

# From a Certificate Chain

The following example shows you how to load a key from a certificate chain.

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            x5c: # Type of key. In this case, the key from a a certificate chain.
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                value: |
                        -----BEGIN CERTIFICATE-----
                        MIID8DCCAtigAwIBAgIDAjqDMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT
                        MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
                        YWwgQ0EwHhcNMTMwNDA1MTUxNTU2WhcNMTYxMjMxMjM1OTU5WjBJMQswCQYDVQQG
                        EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
                        bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
                        AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
                        VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
                        h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
                        ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
                        EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
                        DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7
                        qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wDgYD
                        VR0PAQH/BAQDAgEGMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDov
                        L2cuc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwNQYDVR0fBC4wLDAqoCig
                        JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMBcGA1UdIAQQ
                        MA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQsFAAOCAQEAqvqpIM1qZ4PtXtR+
                        3h3Ef+AlBgDFJPupyC1tft6dgmUsgWM0Zj7pUsIItMsv91+ZOmqcUHqFBYx90SpI
                        hNMJbHzCzTWf84LuUt5oX+QAihcglvcpjZpNy6jehsgNb1aHA30DP9z6eX0hGfnI
                        Oi9RdozHQZJxjyXON/hKTAAj78Q1EK7gI4BzfE00LshukNYQHpmEcxpw8u1VDu4X
                        Bupn7jLrLN1nBz/2i8Jw3lsA5rsb0zYaImxssDVCbJAJPZPpZAkiDoUGn8JzIdPm
                        X4DkjYUiOnMDsWCOrmji9D6X52ASCWg23jrW4kOVWzeBkoEfu43XrVJkFleW2V40
                        fsg12A==
                        -----END CERTIFICATE-----
                        -----BEGIN CERTIFICATE-----
                        MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
                        MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
                        YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG
                        EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg
                        R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9
                        9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq
                        fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv
                        iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU
                        1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+
                        bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW
                        MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA
                        ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l
                        uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn
                        Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS
                        tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF
                        PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un
                        hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV
                        5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==
                        -----END CERTIFICATE-----
```

# Random Key Creation

This bundle is able to create and rotate keys for you.
These keys are stored in a file and served on demand. When expired, they are updated through a dedicated console command.
If you need, a key may have no expiration time.

Please note that parameters `storage_path` and `key_configuration` are common for all keys.

The key ID (`kid`) is always set. If you add it to the `additional_configuration` list, then this value is ignored. 

Please read [this page](../use/commands.md) to know how to use console commands with these kind of keys.

## RSA Key

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            rsa: # Type of key. In this case, the key is a random RSA key.
                size: 4096 # Key size in bits
                storage_path: "/Path/To/The/Storage/File.key" # Path of the file
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                key_configuration: # You can add custom values 
                    alg: 'RS256'
                    use: 'sig'
```

## EC Key

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            ec: # Type of key. In this case, the key is a random EC key.
                curve: 'P-256' # Curve of the key. P-256, P-384 and P-521 are supported
                storage_path: "/Path/To/The/Storage/File.key" # Path of the file
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                key_configuration: # You can add custom values 
                    alg: 'ES256'
                    use: 'sig'
```

## Oct Key

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            oct: # Type of key. In this case, the key is a random Octet key.
                size: 256 # Key size in bits
                storage_path: "/Path/To/The/Storage/File.key" # Path of the file
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                key_configuration: # You can add custom values 
                    alg: 'HS256'
                    use: 'sig'
```

## OKP Key

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            okp: # Type of key. In this case, the key is a random OKP key.
                curve: 'X25519' # Curve of the key. X25519 and Ed25519 are supported
                storage_path: "/Path/To/The/Storage/File.key" # Path of the file
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                key_configuration: # You can add custom values 
                    alg: 'ECDH-ES'
                    use: 'enc'
```

## None Key

```yml
jose:
    keys:
        key_id: # ID of the key. When loaded, the service "jose.key.key_id" will be created
            none: # Type of key. In this case, the key is a none key.
                storage_path: "/Path/To/The/Storage/File.key" # Path of the file
                is_public: true # Indicates the service will be public or private. This option is availble to all key sources
                key_configuration: # You can add custom values 
                    kid: 'MY_NONE_KEY'
                    use: 'sig'
                    alg: 'none'
```

## Key Rotation

All random keys can be refreshed through a console command after a period of time.

In the following example, the command will generate a new key if the actual key is older than 86400 seconds (24 hrs):

```sh
bin/console spomky-labs:jose:rotate-keys --key="jose.key.key_id" --ttl=86400
```

_Please note that the service `jose.key.key_id` must be a valid random key._

