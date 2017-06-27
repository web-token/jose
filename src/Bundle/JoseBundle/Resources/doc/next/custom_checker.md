Custom Checker
==============

The [spomky-Labs/jose](https://github.com/Spomky-Labs/jose) library provides some claim and header checkers,
but you may need to check claims described in the RFC that are not automatically checked or custom claims.

# Available checkers

Services from the following checkers are available.
However the library also provides (abstract)classes to check other useful claims:

- The token ID (`jti`): `Jose\Checker\JtiChecker`
- The audience (`aud`): `Jose\Checker\AudienceChecker`
- The subject (`sub`): `Jose\Checker\SubjectChecker`

All you have to do is to extends the class if needed and create a service.

In the example below we will create a token ID claim checker from the beginning.
Our application, we want to be sure that all tokens have a token ID (`jti` claim) and that ID is only used once.
We have a token ID manager that provides a method `hasTokenIdBeenSeenBefore($jti)` that returns `true` or `false`.

Every claim checkers have to implement the `Jose\Checker\ClaimCheckerInterface` interface.
For header checkers, you have to implement `Jose\Checker\HeaderCheckerInterface`

```php
<?php

namespace AppBundle\Checker;

use Assert\Assertion;
use Jose\Checker\ClaimCheckerInterface;
use Jose\Component\Core\JWTInterface;

class JtiChecker implements  ClaimCheckerInterface
{
    private $token_manager;
    
    // We inject our token manager
    public function __construct(TokenManager $token_manager)
    {
        $this->token_manager = $token_manager;
    }
    
    /**
     * {@inheritdoc}
     */
    public function checkClaim(JWTInterface $jwt)
    {
        // We verify the claim is available (mandatory)
        Assertion::true($jwt->hasClaim('jti'), 'The claim "jti" is missing.');
        
        //We get the claim and verified if it has been used before
        $jti = $jwt->getClaim('jti');
        Assertion::false($this->token_manager->hasTokenIdBeenSeenBefore($jti), sprintf('Invalid token ID "%s".', $jti));
        
        //We return an array with all claims we checked (in this example we only checked 'jti')
        return ['jti'];
     }
}
```

Then create your service definition and do not forget to inject the token manager.
The alias in the tag is mandatory. This alias will be used to serve the checker to your checker manager

```xml
<?xml version="1.0" ?>

<container xmlns="http://symfony.com/schema/dic/services"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://symfony.com/schema/dic/services http://symfony.com/schema/dic/services/services-1.0.xsd">

    <services>
        <service id="jose.checker.jti" class="AppBundle\Checker\JtiChecker" public="false">
            <argument type="service" id="token_manager"/>
            <tag name="jose.checker.claim" alias="my_jti_checker" />
        </service>
    </services>
</container>
```

Now create your checker manager and enable the `my_jti_checker` you created.

```yml
jose:
    checkers:
        my_checker:
            headers:
                ...
            claims:
                - exp
                - nbf
                - iat
                - my_jti_checker
```
