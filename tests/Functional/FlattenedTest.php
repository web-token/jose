<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Decrypter;
use Jose\Loader;
use Jose\Object\JWEInterface;
use Jose\Object\JWSInterface;
use Jose\Test\TestCase;

/**
 * Class FlattenedTest.
 *
 * @group Functional
 */
class FlattenedTest extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.5
     */
    public function testLoadFlattenedJWE()
    {
        $decrypter = Decrypter::createDecrypter(['A128KW'], ['A128CBC-HS256'], ['DEF']);

        $loader = new Loader();
        $loaded = $loader->load('{"protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","unprotected":{"jku":"https://server.example.com/keys.jwks"},"header":{"alg":"A128KW","kid":"7"},"encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ","iv":"AxY8DCtDaGlsbGljb3RoZQ","ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY","tag":"Mz-VPPyU4RlcuYv1IwIvzw"}');

        $this->assertInstanceOf(JWEInterface::class, $loaded);
        $this->assertEquals('A128KW', $loaded->getRecipient(0)->getHeader('alg'));
        $this->assertEquals('A128CBC-HS256', $loaded->getSharedProtectedHeader('enc'));
        $this->assertNull($loaded->getPayload());

        $decrypter->decryptUsingKeySet($loaded, $this->getSymmetricKeySet(), $index);

        $this->assertEquals(0, $index);
        $this->assertEquals('Live long and prosper.', $loaded->getPayload());
    }

    /**
     * @see https://tools.ietf.org/html/rfc7516#appendix-A.5
     */
    public function testLoadFlattenedJWS()
    {
        $loader = new Loader();
        $loaded = $loader->load('{"payload":"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ","protected":"eyJhbGciOiJFUzI1NiJ9","header":{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},"signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}');

        $this->assertInstanceOf(JWSInterface::class, $loaded);
        $this->assertEquals('ES256', $loaded->getSignature(0)->getProtectedHeader('alg'));
        $this->assertEquals(['iss' => 'joe', 'exp' => 1300819380, 'http://example.com/is_root' => true], $loaded->getPayload());
    }
}
