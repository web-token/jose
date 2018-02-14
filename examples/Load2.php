<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

require_once __DIR__.'/../vendor/autoload.php';

use Jose\Checker\AudienceChecker;
use Jose\Factory\CheckerManagerFactory;
use Jose\Factory\JWKFactory;
use Jose\Loader;

// In this example, our input is a JWS string in compact serialization format
// See Signature2.php to know to generate such string
$input = '{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"foo":"bar","123":"ABC"},"signature":"WXfhjDeRv-PCm-5eIgsTkVkUiCXsVe5FODvYjwKHEofZuzJteiNtiDTuSTOKrbsjXIEDbkP8BvYtToZJikjVvw"}';

// The payload is detached.
$detached_payload = 'Live long and prosper.';

// To verify a JWS, we need a key.
// We create our key object (JWK) using a shared key
$key = JWKFactory::createFromValues([
    'kty' => 'oct',
    'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
]);

// We load the input and we verify it.
// HS512 is the only algorithm we allow
// Now the variable $jws contains a JWSInterface object
$loader = new Loader();
$jws = $loader->loadAndVerifySignatureUsingKeyAndDetachedPayload(
    $input,
    $key,
    ['HS512'],
    $detached_payload
);

// Note that if the input contain claims, these claims have to be checked.
// We create a Claim Checker Manager and we want to check the claims 'exp', 'iat' and 'nbf'.
// We also want to check if the protected header 'crit' is present.
//
$checker = CheckerManagerFactory::createClaimCheckerManager(
    ['exp', 'iat', 'nbf'],
    ['crit']
);

// We can add other claim checkers. We add one for the 'aud' claim.
$checker->addClaimChecker(new AudienceChecker('You'));

// We check our JWS. The second argument is the index of the signatures headers to check (0 = the first signature headers).
// This method will throw an exception in case of failure (e.g. expired JWS).
$checker->checkJWS($jws, 0);

// Our JWS is now verified (signature only as it does not contain claims) and we can use it.
