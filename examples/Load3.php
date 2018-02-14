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

// To decrypt and verify our JWE, we need a JWK (or JWKSet) that contains the private key(s).
// We create our key object (JWK) using an encrypted RSA key stored in a file.
// The key is encrypted and the second argument is the password.
// Additional parameters ('kid' and 'use') are set for this key.
$key = JWKFactory::createFromKeyFile(
    __DIR__.'/../tests/Unit/Keys/RSA/private.encrypted.key',
    'tests',
    [
        'kid' => 'My private RSA key',
        'use' => 'enc',
    ]
);

//The JWE
$input = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiemlwIjoiREVGIn0.ZiRhxN_ED1Ed494P85l6p_cwjbS3vkY_qUqsVKnKROGBJVLtyLGKTUgH8PF3wT4WJZlsw8hze_RLf_4ryojuVBMiaJ4wqVLupOH_X00LdKN5ggVeJNiXhu7okpH0osPyWycwlkaH8cAYOA2MUFOZUw8ZvReZULZPswWKnCA7y-yCig0BjTE3WA8B8f66ccPjyK9OYOUGw27L8qD7f5F4goeHiPVpvg_Fb3Se8vD2XzY5m29QsV3TWKu34sHQvbBTVqOlOZ0WdXn11jGZUkg6clYc5iNAWt7qRkk6baGz2lg7DZH2ErK0bFRxjEzhL9qpSkhCMurM4i6E5iDQVLb8rA.wxOu_E6b36tlckgkfXZ6iw.GPjZCuq1rZfEE-L8XW3jh0evjaDPyIkpymI6wvIuGJM.XK-Z-_BbYbDDeUf69dThSNHdITqaF-bM1EVakK4e9yg';

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
    ['RSA-OAEP-256'],
    ['A256CBC-HS512']
);

// Now the variable $jwe is a decrypted JWE
