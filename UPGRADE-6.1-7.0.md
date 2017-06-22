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
* `Jose\Algorithm\JWAManagerInterface` removed. Use the concrete class `Jose\Algorithm\JWAManager` instead.
* `Jose\VerifierInterface` removed. Use the concrete class `Jose\Verifier` instead.
* `Jose\SignerInterface` removed. Use the concrete class `Jose\Signer` instead.
* `Jose\DecrypterInterface` removed. Use the concrete class `Jose\Decrypter` instead.
* `Jose\EncdrypterInterface` removed. Use the concrete class `Jose\Encdrypter` instead.
* `Jose\JWTCreatorInterface` removed. Use the concrete class `Jose\JWTCreator` instead.
* `Jose\JWTLoaderInterface` removed. Use the concrete class `Jose\JWTLoader` instead.
* `Jose\Object\JWSInterface` removed. Use the concrete class `Jose\Object\JWS` instead.
* `Jose\Object\JWEInterface` removed. Use the concrete class `Jose\` instead.
* `Jose\Object\RecipientInterface` removed. Use the concrete class `Jose\Object\Recipient` instead.
* `Jose\Object\SignatureInterface` removed. Use the concrete class `Jose\Object\Signature` instead.
* `Jose\Factory\JWKFactoryInterface` removed. Use the concrete class `Jose\Factory\JWKFactory` instead.
* `Jose\Factory\JWSFactoryInterface` removed. Use the concrete class `Jose\Factory\JWSFactory` instead.
* `Jose\Compression\CompressionManagerInterface` removed. Use the concrete class `Jose\Compression\CompressionManager` instead.
* `Jose\Compression\CompressionInterface::getMethodName` renamed to `Jose\Compression\CompressionInterface::name`
* `Jose\Checker\CheckerManagerInterface` removed. Use the concrete class `Jose\Checker\CheckerManager` instead.
* `Jose\Checker\IssuerChecker` removed.
* `Jose\Checker\SubjectChecker` removed.
* `Jose\Checker\JtiChecker` removed.
* The signature of the method `Jose\Decrypter::__construct` changed.
* The method `Jose\Decrypter::createDecrypter` class removed.
* The signature of the method `Jose\Encrypter::__construct` changed.
* The method `Jose\Encrypter::createEncrypter` class removed.
* The signature of the method `Jose\Signer::__construct` changed.
* The method `Jose\Signer::createSigner` class removed.
* The signature of the method `Jose\Verifier::__construct` changed.
* The method `Jose\Verifier::createVerifier` class removed.

## Namesapce Oganization

* `Jose\Compression` is now `Jose\Component\Encryption\Compression`

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
