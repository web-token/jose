<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Encryption\Tests\RFC7520;

use Base64Url\Base64Url;
use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Compression\CompressionMethodsManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\Decrypter;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Tests\AbstractEncryptionTest;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-5.12
 *
 * @group RFC7520
 */
final class A128KWAndA128GCMEncryptionProtectedContentOnlyTest extends AbstractEncryptionTest
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are always different).
     * The output given in the RFC is used and only decrypted.
     */
    public function testA128KWAndA128GCMEncryptionProtectedContentOnly()
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = JWK::create([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128KW',
            'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]);

        $protected_headers = [
        ];

        $headers = [
            'enc' => 'A128GCM',
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
        ];

        $expected_flattened_json = '{"unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8","enc":"A128GCM"},"encrypted_key":"244YHfO_W7RMpQW81UjQrZcq5LSyqiPv","iv":"YihBoVOGsR1l7jCD","ciphertext":"qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHFSP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDsRPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDfrb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4-8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF","tag":"e2m0Vm7JvjK2VpCKXS-kyg"}';
        $expected_json = '{"recipients":[{"encrypted_key":"244YHfO_W7RMpQW81UjQrZcq5LSyqiPv"}],"unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8","enc":"A128GCM"},"iv":"YihBoVOGsR1l7jCD","ciphertext":"qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHFSP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDsRPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDfrb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4-8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF","tag":"e2m0Vm7JvjK2VpCKXS-kyg"}';
        $expected_iv = 'YihBoVOGsR1l7jCD';
        $expected_encrypted_key = '244YHfO_W7RMpQW81UjQrZcq5LSyqiPv';
        $expected_ciphertext = 'qtPIMMaOBRgASL10dNQhOa7Gqrk7Eal1vwht7R4TT1uq-arsVCPaIeFwQfzrSS6oEUWbBtxEasE0vC6r7sphyVziMCVJEuRJyoAHFSP3eqQPb4Ic1SDSqyXjw_L3svybhHYUGyQuTmUQEDjgjJfBOifwHIsDsRPeBz1NomqeifVPq5GTCWFo5k_MNIQURR2Wj0AHC2k7JZfu2iWjUHLF8ExFZLZ4nlmsvJu_mvifMYiikfNfsZAudISOa6O73yPZtL04k_1FI7WDfrb2w7OqKLWDXzlpcxohPVOLQwpA3mFNRKdY-bQz4Z4KX9lfz1cne31N4-8BKmojpw-OdQjKdLOGkC445Fb_K1tlDQXw2sBF';
        $expected_tag = 'e2m0Vm7JvjK2VpCKXS-kyg';

        $keyEncryptionAlgorithmManager = JWAManager::create([new A128KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A128GCM()]);
        $compressionManager = CompressionMethodsManager::create([new Deflate()]);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $loaded_flattened_json = JWELoader::load($expected_flattened_json);
        $loaded_flattened_json = $decrypter->decryptUsingKey($loaded_flattened_json, $private_key);

        $loaded_json = JWELoader::load($expected_json);
        $loaded_json = $decrypter->decryptUsingKey($loaded_json, $private_key);

        $this->assertEquals($expected_ciphertext, Base64Url::encode($loaded_flattened_json->getCiphertext()));
        $this->assertEquals($protected_headers, $loaded_flattened_json->getSharedProtectedHeaders());
        $this->assertEquals($expected_iv, Base64Url::encode($loaded_flattened_json->getIV()));
        $this->assertEquals($expected_encrypted_key, Base64Url::encode($loaded_flattened_json->getRecipient(0)->getEncryptedKey()));
        $this->assertEquals($headers, $loaded_flattened_json->getSharedHeaders());
        $this->assertEquals($expected_tag, Base64Url::encode($loaded_flattened_json->getTag()));

        $this->assertEquals($expected_ciphertext, Base64Url::encode($loaded_json->getCiphertext()));
        $this->assertEquals($protected_headers, $loaded_json->getSharedProtectedHeaders());
        $this->assertEquals($expected_iv, Base64Url::encode($loaded_json->getIV()));
        $this->assertEquals($expected_encrypted_key, Base64Url::encode($loaded_json->getRecipient(0)->getEncryptedKey()));
        $this->assertEquals($headers, $loaded_json->getSharedHeaders());
        $this->assertEquals($expected_tag, Base64Url::encode($loaded_json->getTag()));

        $this->assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        $this->assertEquals($expected_payload, $loaded_json->getPayload());
    }

    /**
     * Same input as before, but we perform the encryption first.
     */
    public function testA128KWAndA128GCMEncryptionProtectedContentOnlyBis()
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = JWK::create([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128KW',
            'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]);

        $protected_headers = [
        ];

        $headers = [
            'enc' => 'A128GCM',
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
        ];

        $keyEncryptionAlgorithmManager = JWAManager::create([new A128KW()]);
        $contentEncryptionAlgorithmManager = JWAManager::create([new A128GCM()]);
        $compressionManager = CompressionMethodsManager::create([new Deflate()]);
        $jweBuilder = $this->getJWEBuilderFactory()->create(['A128KW'], ['A128GCM'], ['DEF']);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager, $compressionManager);

        $jwe = $jweBuilder
            ->withPayload($expected_payload)
            ->withSharedProtectedHeaders($protected_headers)
            ->withSharedHeaders($headers)
            ->addRecipient($private_key)
            ->build();

        $loaded_flattened_json = JWELoader::load($jwe->toFlattenedJSON(0));
        $loaded_flattened_json = $decrypter->decryptUsingKey($loaded_flattened_json, $private_key);

        $loaded_json = JWELoader::load($jwe->toJSON());
        $loaded_json = $decrypter->decryptUsingKey($loaded_json, $private_key);

        $this->assertEquals($protected_headers, $loaded_flattened_json->getSharedProtectedHeaders());
        $this->assertEquals($headers, $loaded_flattened_json->getSharedHeaders());

        $this->assertEquals($protected_headers, $loaded_json->getSharedProtectedHeaders());
        $this->assertEquals($headers, $loaded_json->getSharedHeaders());

        $this->assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        $this->assertEquals($expected_payload, $loaded_json->getPayload());
    }
}
