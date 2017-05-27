# Upgrade from 6.1 to 7.0

## Old PHP Versions Dropped

PHP 5.x and 7.0 support removed.
You need at least PHP 7.1.

Tests on HHVM are not performed anymore.

## `ECDH-ES*` Encryption Algorithms

The library `mdanter/ecc` is not installed by default.
If you need `ECDH-ES*` encryption algorithms, then you have to install it explicitly. 

## Features added

* No feature added

## Deprecations removed

* `Jose\Algorithm\JWAInterface::getAlgorithmName` renamed to `Jose\Algorithm\JWAInterface::name`
* `Jose\Algorithm\JWAManager::isAlgorithmSupported` renamed to `Jose\Algorithm\JWAManager::has`
* `Jose\Algorithm\JWAManager::getAlgorithms` renamed to `Jose\Algorithm\JWAManager::all`
* `Jose\Algorithm\JWAManager::listAlgorithms` renamed to `Jose\Algorithm\JWAManager::list`
* `Jose\Algorithm\JWAManager::getAlgorithm` renamed to `Jose\Algorithm\JWAManager::get`
* `Jose\Algorithm\JWAManager::addAlgorithm` renamed to `Jose\Algorithm\JWAManager::add`
* `Jose\Algorithm\JWAManagerInterface` removed
* `Jose\VerifierInterface` removed
* `Jose\SignerInterface` removed
* `Jose\DecrypterInterface` removed
* `Jose\EncdrypterInterface` removed
* `Jose\JWTCreatorInterface` removed
* `Jose\JWTLoaderInterface` removed
* `Jose\Object\JWSInterface` removed
* `Jose\Object\JWEInterface` removed
* `Jose\Object\RecipientInterface` removed
* `Jose\Object\SignatureInterface` removed
* `Jose\Factory\JWKFactoryInterface` removed
* `Jose\Factory\JWSFactoryInterface` removed
* `Jose\Compression\CompressionManagerInterface` removed
* `Jose\Compression\CompressionInterface::getMethodName` renamed to `Jose\Compression\CompressionInterface::name`
* `Jose\Checker\CheckerManager` removed
* `Jose\Checker\IssuerChecker` removed
* `Jose\Checker\SubjectChecker` removed
* `Jose\Checker\JtiChecker` removed

## Final classes

The following classes are now marked as final.

* `Jose\Checker\AudienceChecker`
* `Jose\Checker\CriticalHeaderChecker`
* `Jose\Checker\ExpirationTimeChecker`
* `Jose\Checker\IssuedAtChecker`
* `Jose\Checker\NotBeforeChecker`
* `Jose\Checker\CheckerManager`

## Typehinting

Every classes of the project has methods and functions have strict type hinting. 
