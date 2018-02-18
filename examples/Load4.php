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
use Jose\Loader;

/******************/
/*   INPUT DATA   */
/******************/

// My direct key.
$key = JWKFactory::createFromValues([
    'kty' => 'oct',
    'k' => 'saH0gFSP4XM_tAP_a5rU9ooHbltwLiJpL4LLLnrqQPw',
]);

//The JWE
$input = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIn0..QwM0qVoagkgHEoMC.RmuWAHKe69RxZJEE4zibnWeAeX8Ib_o.K2F65di0R7F_jOu9hdrsBQ';

/******************/
/*    LET'S GO!   */
/******************/

// We load the input and we try to decrypt it.
// The first argument is our input
// The second argument is our private key
// The third argument is a list of allowed algorithms.
$loader = new Loader();
$jwe = $loader->loadAndDecryptUsingKey(
    $input,
    $key,
    ['dir'],
    ['A256GCM']
);

// Now the variable $jwe is a decrypted JWE
