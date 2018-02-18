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

// We create our key object (JWK) using an encrypted RSA key stored in a file
// Additional parameters ('kid' and 'use') are set for this key.
$key = JWKFactory::createFromKeyFile(
    __DIR__.'/../tests/Unit/Keys/RSA/private.encrypted.key',
    'tests',
    [
        'kid' => 'My Private RSA key',
        'use' => 'sig',
    ]
);

// We create an array of claims.
// This array wil be the payload of the JWS
$claims = [
    'nbf' => time(),
    'iat' => time(),
    'exp' => time() + 3600,
    'iss' => 'Me',
    'aud' => 'You',
    'sub' => 'My friend',
];

$jws = JWSFactory::createJWSToCompactJSON(
    $claims,
    $key,
    [
        'crit' => ['exp', 'aud'],
        'alg' => 'RS256',
    ]
);

// Now the variable $jws contains a our claims signed with our private key
// Please read example Load1.php to know how to load this string and to verify the signature
