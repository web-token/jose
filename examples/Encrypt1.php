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

use Jose\Factory\JWEFactory;
use Jose\Factory\JWKFactory;

// We create our key object (JWK) using a public RSA key stored in a file
// Additional parameters ('kid' and 'use') are set for this key.
$key = JWKFactory::createFromKeyFile(
    __DIR__.'/../tests/Unit/Keys/RSA/public.key',
    null,
    [
        'kid' => 'My Public RSA key',
        'use' => 'enc',
        'alg' => 'RSA-OAEP-256',
    ]
);

// We want to encrypt a very important message
$jwe = JWEFactory::createJWEToCompactJSON(
    '8:00PM, train station',
    $key,
    [
        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256CBC-HS512',
        'zip' => 'DEF',
    ]
);

// Now the variable $jwe contains our message encrypted with the public key passed as argument
