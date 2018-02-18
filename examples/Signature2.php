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

use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;

// We create our key object (JWK) using a shared key
$key = JWKFactory::createFromValues([
    'kty' => 'oct',
    'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
]);

// Ou payload is a simple message.
$jws = JWSFactory::createJWSWithDetachedPayloadToFlattenedJSON(
    'Live long and prosper.',
    $key,
    [
        'alg' => 'HS512',
    ],
    [
        'foo' => 'bar',
        '123' => 'ABC',
    ]
);

// Now the variable $jws contains a our message signed with the private key.
// The payload is not part of the output.
// Please read example Load2.php to know how to load these strings and to verify the signature
// The output contains unprotected headers. That is why it cannot be converted into compact JSON
