<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

include_once __DIR__ . '/../vendor/autoload.php';

use Jose\Component\Encryption\Algorithm\KeyEncryption\A128GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256GCMKW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS256A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS384A192KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Core\JWK;

function testKeyWrappinPerformance(KeyWrappingInterface $alg, JWK $recipient_key)
{
    $header = [
        'alg' => $alg->name(),
        'enc' => 'A128GCM',
        'exp' => time() + 3600,
        'iat' => time(),
        'nbf' => time(),
    ];
    $cek = random_bytes(512 / 8);
    $nb = 100;

    $time_start = microtime(true);
    for ($i = 0; $i < $nb; $i++) {
        $alg->wrapKey($recipient_key, $cek, $header, $header);
    }
    $time_end = microtime(true);

    $time = ($time_end - $time_start) / $nb * 1000;
    printf('%s: %f milliseconds/wrapping'.PHP_EOL, $alg->name(), $time);
}

function testKeyUnwrappingPerformance(KeyWrappingInterface $alg, JWK $recipient_key)
{
    $header = [
        'alg' => $alg->name(),
        'enc' => 'A128GCM',
        'exp' => time() + 3600,
        'iat' => time(),
        'nbf' => time(),
    ];
    $cek = random_bytes(512 / 8);

    $encrypted_cek = $alg->wrapKey($recipient_key, $cek, $header, $header);
    $nb = 100;

    $time_start = microtime(true);
    for ($i = 0; $i < $nb; $i++) {
        $alg->unwrapKey($recipient_key, $encrypted_cek, $header);
    }
    $time_end = microtime(true);

    $time = ($time_end - $time_start) / $nb * 1000;
    printf('%s: %f milliseconds/unwrapping'.PHP_EOL, $alg->name(), $time);
}

function dataKeyWrappinPerformance()
{
    return [
        [
            new A128KW(),
            JWK::create([
            'kty' => 'oct',
            'k'   => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]),
        ],
        [
            new A192KW(),
            JWK::create([
            'kty' => 'oct',
            'k'   => 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX',
        ]),
        ],
        [
            new A256KW(),
            JWK::create([
            'kty' => 'oct',
            'k'   => 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
        ]),
        ],
        [
            new A128GCMKW(),
            JWK::create([
            'kty' => 'oct',
            'k'   => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]),
        ],
        [
            new A192GCMKW(),
            JWK::create([
            'kty' => 'oct',
            'k'   => 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX',
        ]),
        ],
        [
            new A256GCMKW(),
            JWK::create([
            'kty' => 'oct',
            'k'   => 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
        ]),
        ],
        [
            new PBES2HS256A128KW(),
            JWK::create([
            'kty' => 'oct',
            'k'   => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]),
        ],
        [
            new PBES2HS384A192KW(),
            JWK::create([
            'kty' => 'oct',
            'k'   => 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX',
        ]),
        ],
        [
            new PBES2HS512A256KW(),
            JWK::create([
            'kty' => 'oct',
            'k'   => 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
        ]),
        ],
    ];
}

$environments = dataKeyWrappinPerformance();

print_r('##################################'.PHP_EOL);
print_r('# KEY WRAPPING PERFORMANCE TESTS #'.PHP_EOL);
print_r('##################################'.PHP_EOL);

foreach ($environments as $environment) {
    testKeyWrappinPerformance($environment[0], $environment[1]);
}
foreach ($environments as $environment) {
    testKeyUnwrappingPerformance($environment[0], $environment[1]);
}

print_r('##################################'.PHP_EOL);
