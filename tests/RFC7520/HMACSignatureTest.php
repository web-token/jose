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

use Jose\Factory\JWSFactory;
use Jose\Loader;
use Jose\Object\JWK;
use Jose\Signer;
use Jose\Verifier;

/**
 * @see https://tools.ietf.org/html/rfc7520#section-4.4
 * @see https://tools.ietf.org/html/rfc7520#section-4.5
 * @see https://tools.ietf.org/html/rfc7520#section-4.6
 * @see https://tools.ietf.org/html/rfc7520#section-4.7
 *
 * @group HMAC
 * @group RFC7520
 */
class HMACSignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.4
     */
    public function testHS256()
    {
        /*
         * Payload
         * Symmetric Key
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         * @see https://tools.ietf.org/html/rfc7520#section-4.4.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.4.2
         */
        $headers = [
            'alg' => 'HS256',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
        ];

        $jws = JWSFactory::createJWS($payload);
        $jws = $jws->addSignatureInformation($key, $headers);

        $signer = Signer::createSigner(['HS256']);
        $signer->sign($jws);

        $verifer = Verifier::createVerifier(['HS256']);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.4.3
         */
        $expected_compact_json = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0';
        $expected_flattened_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}';
        $expected_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}]}';

        $this->assertEquals($expected_compact_json, $jws->toCompactJSON(0));

        // We decode the json to compare the 2 arrays otherwise the test may fail as the order may be different
        $this->assertEquals(json_decode($expected_flattened_json, true), json_decode($jws->toFlattenedJSON(0), true));
        $this->assertEquals(json_decode($expected_json, true), json_decode($jws->toJSON(), true));

        $loader = new Loader();
        $loaded_compact_json = $loader->load($expected_compact_json);
        $verifer->verifyWithKey($loaded_compact_json, $key);

        $loaded_flattened_json = $loader->load($expected_flattened_json);
        $verifer->verifyWithKey($loaded_flattened_json, $key);

        $loaded_json = $loader->load($expected_json);
        $verifer->verifyWithKey($loaded_json, $key);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.5
     */
    public function testHS256WithDetachedPayload()
    {
        /*
         * Payload
         * Symmetric Key
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         * @see https://tools.ietf.org/html/rfc7520#section-4.5.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.5.2
         */
        $headers = [
            'alg' => 'HS256',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
        ];

        $jws = JWSFactory::createJWS($payload, true);
        $jws = $jws->addSignatureInformation($key, $headers);

        $signer = Signer::createSigner(['HS256']);
        $signer->sign($jws);

        $verifer = Verifier::createVerifier(['HS256']);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.5.3
         */
        $expected_compact_json = 'eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9..s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0';
        $expected_flattened_json = '{"protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}';
        $expected_json = '{"signatures":[{"protected":"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9","signature":"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"}]}';

        $this->assertEquals($expected_compact_json, $jws->toCompactJSON(0));

        // We decode the json to compare the 2 arrays otherwise the test may fail as the order may be different
        $this->assertEquals(json_decode($expected_flattened_json, true), json_decode($jws->toFlattenedJSON(0), true));

        $this->assertEquals(json_decode($expected_json, true), json_decode($jws->toJSON(), true));

        $loader = new Loader();
        $loaded_compact_json = $loader->load($expected_compact_json);
        $verifer->verifyWithKey($loaded_compact_json, $key, $payload);

        $loaded_flattened_json = $loader->load($expected_flattened_json);
        $verifer->verifyWithKey($loaded_flattened_json, $key, $payload);

        $loaded_json = $loader->load($expected_json);
        $verifer->verifyWithKey($loaded_json, $key, $payload);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.6
     */
    public function testHS256WithUnprotectedHeaders()
    {
        /*
         * Payload
         * Symmetric Key
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         * @see https://tools.ietf.org/html/rfc7520#section-4.6.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.6.2
         */
        $protected_headers = [
            'alg' => 'HS256',
        ];
        $unprotected_headers = [
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
        ];

        $jws = JWSFactory::createJWS($payload);
        $jws = $jws->addSignatureInformation($key, $protected_headers, $unprotected_headers);

        $signer = Signer::createSigner(['HS256']);
        $signer->sign($jws);

        $verifer = Verifier::createVerifier(['HS256']);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.6.3
         */
        $expected_flattened_json = '{"payload": "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","protected": "eyJhbGciOiJIUzI1NiJ9","header": {"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"},"signature": "bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"}';
        $expected_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"},"signature":"bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"}]}';

        // We decode the json to compare the 2 arrays otherwise the test may fail as the order may be different
        $this->assertEquals(json_decode($expected_flattened_json, true), json_decode($jws->toFlattenedJSON(0), true));
        $this->assertEquals(json_decode($expected_json, true), json_decode($jws->toJSON(), true));

        $loader = new Loader();
        $loaded_flattened_json = $loader->load($expected_flattened_json);
        $verifer->verifyWithKey($loaded_flattened_json, $key);

        $loaded_json = $loader->load($expected_json);
        $verifer->verifyWithKey($loaded_json, $key);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7520#section-4.7
     */
    public function testHS256WithoutProtectedHeaders()
    {
        /*
         * Payload
         * Symmetric Key
         * @see https://tools.ietf.org/html/rfc7520#section-3.5
         * @see https://tools.ietf.org/html/rfc7520#section-4.7.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $key = new JWK([
            'kty' => 'oct',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
            'use' => 'sig',
            'alg' => 'HS256',
            'k' => 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg',
        ]);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.7.2
         */
        $unprotected_headers = [
            'alg' => 'HS256',
            'kid' => '018c0ae5-4d9b-471b-bfd6-eef314bc7037',
        ];

        $jws = JWSFactory::createJWS($payload);
        $jws = $jws->addSignatureInformation($key, [], $unprotected_headers);

        $signer = Signer::createSigner(['HS256']);
        $signer->sign($jws);

        $verifer = Verifier::createVerifier(['HS256']);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.7.3
         */
        $expected_flattened_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","header":{"alg":"HS256","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"},"signature":"xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk"}';
        $expected_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"header":{"alg":"HS256","kid":"018c0ae5-4d9b-471b-bfd6-eef314bc7037"},"signature":"xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk"}]}';

        // We decode the json to compare the 2 arrays otherwise the test may fail as the order may be different
        $this->assertEquals(json_decode($expected_flattened_json, true), json_decode($jws->toFlattenedJSON(0), true));
        $this->assertEquals(json_decode($expected_json, true), json_decode($jws->toJSON(), true));

        $loader = new Loader();
        $loaded_flattened_json = $loader->load($expected_flattened_json);
        $verifer->verifyWithKey($loaded_flattened_json, $key);

        $loaded_json = $loader->load($expected_json);
        $verifer->verifyWithKey($loaded_json, $key);
    }
}
