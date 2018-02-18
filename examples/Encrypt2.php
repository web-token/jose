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

// We create our key object (JWK) using an octet key.
// Additional parameters ('kid' and 'use') are set for this key.
$key = JWKFactory::createFromValues([
    'kty' => 'oct',
    'k' => 'saH0gFSP4XM_tAP_a5rU9ooHbltwLiJpL4LLLnrqQPw',
    'alg' => 'A256GCM',
]);

// We want to encrypt a very important message
//
$jwe = JWEFactory::createJWEToCompactJSON(
    '8:00PM, train station',
    $key,
    [
        'alg' => 'dir',
        'enc' => 'A256GCM',
        'zip' => 'DEF',
    ]
);

// Now the variable $jwe contains our message encrypted with the public key passed as argument
// It contains something like "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIn0..QwM0qVoagkgHEoMC.RmuWAHKe69RxZJEE4zibnWeAeX8Ib_o.K2F65di0R7F_jOu9hdrsBQ"
// See example Load4.php to know how to decrypt this JWE.
