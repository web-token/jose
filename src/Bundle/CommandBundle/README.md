Jose Bundle
===========

Help me out for a couple of :beers:!

[![Beerpay](https://beerpay.io/Spomky-Labs/jose-bundle/badge.svg?style=beer-square)](https://beerpay.io/Spomky-Labs/jose-bundle)  [![Beerpay](https://beerpay.io/Spomky-Labs/jose-bundle/make-wish.svg?style=flat-square)](https://beerpay.io/Spomky-Labs/jose-bundle?focus=wish)

----

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/Spomky-Labs/jose-bundle/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/Spomky-Labs/jose-bundle/?branch=master)
[![Build Status](https://travis-ci.org/Spomky-Labs/jose-bundle.svg?branch=master)](https://travis-ci.org/Spomky-Labs/jose-bundle)

[![HHVM Status](http://hhvm.h4cc.de/badge/Spomky-Labs/jose-bundle.png)](http://hhvm.h4cc.de/package/Spomky-Labs/jose-bundle)
[![PHP 7 ready](http://php7ready.timesplinter.ch/Spomky-Labs/jose-bundle/badge.svg)](https://travis-ci.org/Spomky-Labs/jose-bundle)

[![SensioLabsInsight](https://insight.sensiolabs.com/projects/5398e4ca-1a48-4186-9410-f44f3f850a05/big.png)](https://insight.sensiolabs.com/projects/5398e4ca-1a48-4186-9410-f44f3f850a05)

[![Latest Stable Version](https://poser.pugx.org/Spomky-Labs/jose-bundle/v/stable.png)](https://packagist.org/packages/Spomky-Labs/jose-bundle)
[![Total Downloads](https://poser.pugx.org/Spomky-Labs/jose-bundle/downloads.png)](https://packagist.org/packages/Spomky-Labs/jose-bundle)
[![Latest Unstable Version](https://poser.pugx.org/Spomky-Labs/jose-bundle/v/unstable.png)](https://packagist.org/packages/Spomky-Labs/jose-bundle)
[![License](https://poser.pugx.org/Spomky-Labs/jose-bundle/license.png)](https://packagist.org/packages/Spomky-Labs/jose-bundle)

This Symfony bundle provides services to create, load, verify or decrypt JWT.
It uses [spomky-Labs/jose](https://github.com/Spomky-Labs/jose) to ease encryption/decryption and signature/verification of JWS and JWE.

# The Release Process

The release process [is described here](doc/Release.md).

# Prerequisites

This library needs at least:
* ![PHP 5.6+](https://img.shields.io/badge/PHP-5.6%2B-ff69b4.svg)
* Symfony 2.7+ or Symfony 3.0+

# Continuous Integration

It has been successfully tested using `PHP 5.6`, `PHP 7` and `HHVM`.

We also track bugs and code quality using [Scrutinizer-CI](https://scrutinizer-ci.com/g/Spomky-Labs/jose-bundle/) and [Sensio Insight](https://insight.sensiolabs.com/projects/5398e4ca-1a48-4186-9410-f44f3f850a05).

Coding Standards are verified by [StyleCI](https://styleci.io/repos/28856829).

Code coverage is not performed.
We rely on tests performed on the library and we only have implemented `Behavior driven development` (BDD) to test this bundle. 

# Installation

The preferred way to install this library is to rely on Composer:

```sh
composer require spomky-labs/jose-bundle
```

Then, add the bundle into your kernel:

```php
<?php declare(strict_types=1);

use Symfony\Component\HttpKernel\Kernel;

class AppKernel extends Kernel
{
    public function registerBundles()
    {
        $bundles = [
            ...
            new SpomkyLabs\JoseBundle\SpomkyLabsJoseBundle(),
        ];

        return $bundles;
    }
}
```

# Configuration

This bundle needs to be configured. Please [see this page](Resources/doc/Configuration.md) to know how to configure it.

# How to use

Have a look at [this page](Resources/doc/Use.md) to know hot to configure and use this bundle.

# Bundle Integration

This bundle provides a Configuration Helper.
This helper provides an easy way to create all services through the configuration of another bundle.
 
Please read [this page](Resources/doc/config/configuration_helper.md) to know how to easily configure the bundle from another bundle.


# Contributing

Requests for new features, bug fixed and all other ideas to make this library useful are welcome.
The best contribution you could provide is by fixing the [opened issues where help is wanted](https://github.com/Spomky-Labs/JoseBundle/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)

Please make sure to [follow these best practices](Resources/doc/Contributing.md).

# Licence

This software is release under [MIT licence](LICENSE).
