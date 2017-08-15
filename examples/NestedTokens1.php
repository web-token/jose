<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

require_once __DIR__.'/../vendor/autoload.php';

use Jose\Factory\JWEFactory;
use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;

//Encryption key (public key certificate of the receiver)
$encryptionKey = JWKFactory::createFromKeyFile( 'path/to/key.crt' );

//Signature key (private key of sender)
$signatureKey = JWKFactory::createFromKeyFile( 'path/to/key.key' );

//Claims
$claims = [
    'nbf' => time(),
    'iat' => time(),
    'exp' => time() + 3600,
    'iss' => 'Me',
    'aud' => 'You',
    'sub' => 'My friend',
];

//JWS creation
$jws = JWSFactory::createJWSToCompactJSON(
    $claims,
    $signatureKey,
    [
        'crit' => ['exp', 'aud'],
        'alg'  => 'RS256',
    ]
);

//JWE creation with JWS as payload
$jwe = JWEFactory::createJWEToCompactJSON(
    $jws,
    $encryptionKey,
    [
        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256CBC-HS512',
        'zip' => 'DEF',
    ]
);
var_dump($jwe);
