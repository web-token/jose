Console Commands
================

The project comes with console commands.
They are available:
* as a standalone command
* through the dedicated Symfony console command
* as a PHAR (PHP Archive)

#Available Commands

Available commands are:

* `key:analyze`:         JWK quality analyzer.
* `key:convert:pkcs1`:   Converts a RSA or EC key into PKCS#1 key.
* `key:generate:ec`:     Generate an EC key (JWK format)
* `key:generate:oct`:    Generate a octet key (JWK format)
* `key:generate:okp`:    Generate an Octet Key Pair key (JWK format)
* `key:generate:rsa`:    Generate a RSA key (JWK format)
* `key:load:key`:        Loads a key from a key file (JWK format)
* `key:load:p12`:        Load a key from a P12 certificate file.
* `key:load:x509`:       Load a key from a X.509 certificate file.
* `key:optimize`:        Optimize a RSA key by calculating additional primes (CRT).
* `key:thumbprint`:      Get the thumbprint of a JWK key.
* `keyset:analyze`:      JWKSet quality analyzer.
* `keyset:generate:ec`:  Generate an EC key set (JWKSet format)
* `keyset:generate:oct`: Generate a key set with octet keys (JWK format)
* `keyset:generate:okp`: Generate a key set with Octet Key Pairs keys (JWKSet format)
* `keyset:generate:rsa`: Generate a key set with RSA keys (JWK format)
* `keyset:load:jku`:     Loads a key set from an url.
* `keyset:load:x5u`:     Loads a key set from an url.

You will get more information by following the command name with `--help`.

# Installation

## Standolane Console Command

You will find the standalone console command in the `bin` folder.

```sh
./bin/jose
```

# Symfony Console Command

To enable the commands on a Symfony application, you have to add the associated bundle into your kernel:

```php
// app/AppKernel.php

class AppKernel extends Kernel
{
    public function registerBundles()
    {
        $bundles = [
            ...
            new Jose\Bundle\Console\ConsoleBundle(),
        ];

        return $bundles;
    }
    ...
}
```

And then execute the following command:

```sh
./bin/console
```

# PHAR Package Compilation

To compile the console command and get a PHAR file, you must first install Box:

```sh
curl -LSs https://box-project.github.io/box2/installer.php | php
```

If everything is fine, the box command should be available:

```sh
box --version
```

To get an optimized application, you have to remove all development dependencies and adapt the autoloader.
**This step is not mandatory but highly recommended**.

```sh
composer update --no-dev --optimize-autoloader
```

Then you can build the archive. This step takes apprximatly between two and five minutes.

```sh
box build
```

When the compilation is finished, you will get a `jose.phar` file at the project root folder.
You can move this file wherever you want (e.g. `/usr/local/bin`).

To use it, just execute the following line:

```sh
jose.phar
```
