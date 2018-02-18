<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\RFC7520;

use Base64Url\Base64Url;
use Jose\Decrypter;
use Jose\Encrypter;
use Jose\Factory\JWEFactory;
use Jose\Loader;
use Jose\Object\JWK;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-5.11
 *
 * @group RFC7520
 */
class A128KWAndA128GCMEncryptionWithSpecificProtectedHeaderValuesTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Please note that we cannot the encryption and get the same result as the example (IV, TAG and other data are always different).
     * The output given in the RFC is used and only decrypted.
     */
    public function testA128KWAndA128GCMEncryptionWithSpecificProtectedHeaderValues()
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = new JWK([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128KW',
            'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]);

        $protected_headers = [
            'enc' => 'A128GCM',
        ];

        $headers = [
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
        ];

        $expected_flattened_json = '{"protected":"eyJlbmMiOiJBMTI4R0NNIn0","unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8"},"encrypted_key":"jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H","iv":"WgEJsDS9bkoXQ3nR","ciphertext":"lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2DM3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9OCCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf","tag":"fNYLqpUe84KD45lvDiaBAQ"}';
        $expected_json = '{"recipients":[{"encrypted_key":"jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H"}],"unprotected":{"alg":"A128KW","kid":"81b20965-8332-43d9-a468-82160ad91ac8"},"protected":"eyJlbmMiOiJBMTI4R0NNIn0","iv":"WgEJsDS9bkoXQ3nR","ciphertext":"lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2DM3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9OCCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf","tag":"fNYLqpUe84KD45lvDiaBAQ"}';
        $expected_iv = 'WgEJsDS9bkoXQ3nR';
        $expected_encrypted_key = 'jJIcM9J-hbx3wnqhf5FlkEYos0sHsF0H';
        $expected_ciphertext = 'lIbCyRmRJxnB2yLQOTqjCDKV3H30ossOw3uD9DPsqLL2DM3swKkjOwQyZtWsFLYMj5YeLht_StAn21tHmQJuuNt64T8D4t6C7kC9OCCJ1IHAolUv4MyOt80MoPb8fZYbNKqplzYJgIL58g8N2v46OgyG637d6uuKPwhAnTGm_zWhqc_srOvgiLkzyFXPq1hBAURbc3-8BqeRb48iR1-_5g5UjWVD3lgiLCN_P7AW8mIiFvUNXBPJK3nOWL4teUPS8yHLbWeL83olU4UAgL48x-8dDkH23JykibVSQju-f7e-1xreHWXzWLHs1NqBbre0dEwK3HX_xM0LjUz77Krppgegoutpf5qaKg3l-_xMINmf';
        $expected_tag = 'fNYLqpUe84KD45lvDiaBAQ';

        $decrypter = Decrypter::createDecrypter(['A128KW'], ['A128GCM']);

        $loader = new Loader();
        $loaded_flattened_json = $loader->load($expected_flattened_json);
        $decrypter->decryptUsingKey($loaded_flattened_json, $private_key);

        $loaded_json = $loader->load($expected_json);
        $decrypter->decryptUsingKey($loaded_json, $private_key);

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
    public function testA128KWAndA128GCMEncryptionWithSpecificProtectedHeaderValuesBis()
    {
        $expected_payload = "You can trust us to stick with you through thick and thin\xe2\x80\x93to the bitter end. And you can trust us to keep any secret of yours\xe2\x80\x93closer than you keep it yourself. But you cannot trust us to let you face trouble alone, and go off without a word. We are your friends, Frodo.";

        $private_key = new JWK([
            'kty' => 'oct',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
            'use' => 'enc',
            'alg' => 'A128KW',
            'k' => 'GZy6sIZ6wl9NJOKB-jnmVQ',
        ]);

        $protected_headers = [
            'enc' => 'A128GCM',
        ];

        $headers = [
            'alg' => 'A128KW',
            'kid' => '81b20965-8332-43d9-a468-82160ad91ac8',
        ];

        $jwe = JWEFactory::createJWE($expected_payload, $protected_headers, $headers);
        $encrypter = Encrypter::createEncrypter(['A128KW'], ['A128GCM']);

        $jwe = $jwe->addRecipientInformation(
            $private_key
        );

        $encrypter->encrypt($jwe);

        $decrypter = Decrypter::createDecrypter(['A128KW'], ['A128GCM']);

        $loader = new Loader();
        $loaded_flattened_json = $loader->load($jwe->toFlattenedJSON(0));
        $decrypter->decryptUsingKey($loaded_flattened_json, $private_key);

        $loaded_json = $loader->load($jwe->toJSON());
        $decrypter->decryptUsingKey($loaded_json, $private_key);

        $this->assertEquals($protected_headers, $loaded_flattened_json->getSharedProtectedHeaders());
        $this->assertEquals($headers, $loaded_flattened_json->getSharedHeaders());

        $this->assertEquals($protected_headers, $loaded_json->getSharedProtectedHeaders());
        $this->assertEquals($headers, $loaded_json->getSharedHeaders());

        $this->assertEquals($expected_payload, $loaded_flattened_json->getPayload());
        $this->assertEquals($expected_payload, $loaded_json->getPayload());
    }
}
