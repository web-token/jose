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
 * @see https://tools.ietf.org/html/rfc7520#section-4.3
 *
 * @group RFC7520
 */
class ECDSASignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Please note that we cannot create the signature and get the same result as the example (ECDSA signatures are always different).
     * This test case create a signature and verifies it.
     * Then the output given in the RFC is used and verified.
     * This way, we can say that the library is able to create/verify ECDSA signatures and verify signature from test vectors.
     */
    public function testES512()
    {
        /*
         * Payload
         * EC public key
         * @see https://tools.ietf.org/html/rfc7520#section-3.2
         * @see https://tools.ietf.org/html/rfc7520#section-4.3.1
         */
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $private_key = new JWK([
            'kty' => 'EC',
            'kid' => 'bilbo.baggins@hobbiton.example',
            'use' => 'sig',
            'crv' => 'P-521',
            'x' => 'AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt',
            'y' => 'AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1',
            'd' => 'AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt',
        ]);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.3.2
         */
        $headers = [
            'alg' => 'ES512',
            'kid' => 'bilbo.baggins@hobbiton.example',
        ];

        $jws = JWSFactory::createJWS($payload);
        $jws = $jws->addSignatureInformation($private_key, $headers);

        $signer = Signer::createSigner(['ES512']);
        $signer->sign($jws);

        $verifer = Verifier::createVerifier(['ES512']);

        $verifer->verifyWithKey($jws, $private_key);

        /*
         * Header
         * @see https://tools.ietf.org/html/rfc7520#section-4.3.3
         */
        $expected_compact_json = 'eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2';
        $expected_flattened_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","protected":"eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9","signature":"AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"}';
        $expected_json = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[{"protected":"eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhbXBsZSJ9","signature":"AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"}]}';

        $loader = new Loader();
        $loaded_compact_json = $loader->load($expected_compact_json);
        $verifer->verifyWithKey($loaded_compact_json, $private_key);

        $loaded_flattened_json = $loader->load($expected_flattened_json);
        $verifer->verifyWithKey($loaded_flattened_json, $private_key);

        $loaded_json = $loader->load($expected_json);
        $verifer->verifyWithKey($loaded_json, $private_key);
    }
}
