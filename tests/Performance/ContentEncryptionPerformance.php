<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

include_once __DIR__.'/../../vendor/autoload.php';

use Base64Url\Base64Url;
use Jose\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Algorithm\ContentEncryption\A128GCM;
use Jose\Algorithm\ContentEncryption\A192CBCHS384;
use Jose\Algorithm\ContentEncryption\A192GCM;
use Jose\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Algorithm\ContentEncryption\A256GCM;
use Jose\Algorithm\ContentEncryptionAlgorithmInterface;

function testContentEncryptionPerformance(ContentEncryptionAlgorithmInterface $alg)
{
    $header = Base64Url::encode(json_encode([
        'alg' => 'A128GCM',
        'enc' => $alg->getAlgorithmName(),
        'exp' => time() + 3600,
        'iat' => time(),
        'nbf' => time(),
    ]));
    $data = random_bytes(1024);
    $iv = random_bytes($alg->getIVSize() / 8);
    $cek = random_bytes($alg->getCEKSize() / 8);
    $aad = random_bytes(128);
    $nb = 100;

    $time_start = microtime(true);
    for ($i = 0; $i < $nb; ++$i) {
        $alg->encryptContent($data, $cek, $iv, $aad, $header, $tag);
    }
    $time_end = microtime(true);

    $time = ($time_end - $time_start) / $nb * 1000;
    printf('%s: %f milliseconds/encryption'.PHP_EOL, $alg->getAlgorithmName(), $time);
}

function testContentDecryptionPerformance(ContentEncryptionAlgorithmInterface $alg)
{
    $header = Base64Url::encode(json_encode([
        'alg' => 'A128GCM',
        'enc' => $alg->getAlgorithmName(),
        'exp' => time() + 3600,
        'iat' => time(),
        'nbf' => time(),
    ]));
    $data = random_bytes(1024);
    $iv = random_bytes($alg->getIVSize() / 8);
    $cek = random_bytes($alg->getCEKSize() / 8);
    $aad = random_bytes(128);
    $encrypted_content = $alg->encryptContent($data, $cek, $iv, $aad, $header, $tag);
    $nb = 100;

    $time_start = microtime(true);
    for ($i = 0; $i < $nb; ++$i) {
        $alg->decryptContent($encrypted_content, $cek, $iv, $aad, $header, $tag);
    }
    $time_end = microtime(true);

    $time = ($time_end - $time_start) / $nb * 1000;
    printf('%s: %f milliseconds/decryption'.PHP_EOL, $alg->getAlgorithmName(), $time);
}

function dataContentEncryptionPerformance()
{
    return [
        [new A128CBCHS256()],
        [new A192CBCHS384()],
        [new A256CBCHS512()],
        [new A128GCM()],
        [new A192GCM()],
        [new A256GCM()],
    ];
}

$environments = dataContentEncryptionPerformance();

print_r('########################################'.PHP_EOL);
print_r('# CONTENT ENCRYPTION PERFORMANCE TESTS #'.PHP_EOL);
print_r('########################################'.PHP_EOL);

foreach ($environments as $environment) {
    testContentEncryptionPerformance($environment[0]);
}
foreach ($environments as $environment) {
    testContentDecryptionPerformance($environment[0]);
}

print_r('########################################'.PHP_EOL);
