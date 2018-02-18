<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Base64Url\Base64Url;
use Jose\Algorithm\Signature\ES256;
use Jose\Algorithm\Signature\ES384;
use Jose\Algorithm\Signature\ES512;
use Jose\KeyConverter\KeyConverter;
use Jose\Object\JWK;

/**
 * @group ECDSA
 * @group Unit
 *
 * The values of these tests come from the JWS specification
 */
class ECDSASignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Wrong key type.
     */
    public function testInvalidKey()
    {
        $key = new JWK([
            'kty' => 'RSA',
        ]);

        $ecdsa = new ES256();
        $data = 'Live long and Prosper.';

        $ecdsa->sign($key, $data);
    }

    public function testES256Verify()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        $ecdsa = new ES256();
        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';

        $sign = $ecdsa->sign($key, $data);

        $this->assertTrue($ecdsa->verify($key, $data, $sign));
        $this->assertTrue($ecdsa->verify($key, $data, Base64Url::decode($signature)));
    }

    public function testES256SignVerify()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        $ecdsa = new ES256();

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = $ecdsa->sign($key, $data);

        $this->assertTrue($ecdsa->verify($key, $data, $signature));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The EC key is not private
     */
    public function testKeyNotPrivate()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        $ecdsa = new ES256();

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $ecdsa->sign($key, $data);
    }

    public function testES256SignAndVerify()
    {
        $public_key = new JWK(KeyConverter::loadFromKeyFile('file://'.__DIR__.DIRECTORY_SEPARATOR.'..'.DIRECTORY_SEPARATOR.'Keys'.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es256.key'));
        $private_key = new JWK(KeyConverter::loadFromKeyFile('file://'.__DIR__.DIRECTORY_SEPARATOR.'..'.DIRECTORY_SEPARATOR.'Keys'.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es256.key'));

        $ecdsa = new ES256();
        $data = 'Live long and Prosper.';
        $signature = $ecdsa->sign($private_key, $data);

        $this->assertTrue($ecdsa->verify($public_key, $data, $signature));
    }

    public function testES384SignAndVerify()
    {
        $public_key = new JWK(KeyConverter::loadFromKeyFile('file://'.__DIR__.DIRECTORY_SEPARATOR.'..'.DIRECTORY_SEPARATOR.'Keys'.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es384.key'));
        $private_key = new JWK(KeyConverter::loadFromKeyFile('file://'.__DIR__.DIRECTORY_SEPARATOR.'..'.DIRECTORY_SEPARATOR.'Keys'.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es384.key'));

        $ecdsa = new ES384();
        $data = 'Live long and Prosper.';
        $signature = $ecdsa->sign($private_key, $data);

        $this->assertTrue($ecdsa->verify($public_key, $data, $signature));
    }

    public function testES512SignAndVerify()
    {
        $public_key = new JWK(KeyConverter::loadFromKeyFile('file://'.__DIR__.DIRECTORY_SEPARATOR.'..'.DIRECTORY_SEPARATOR.'Keys'.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es512.key'));
        $private_key = new JWK(KeyConverter::loadFromKeyFile('file://'.__DIR__.DIRECTORY_SEPARATOR.'..'.DIRECTORY_SEPARATOR.'Keys'.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es512.key'));

        $ecdsa = new ES512();
        $data = 'Live long and Prosper.';
        $signature = $ecdsa->sign($private_key, $data);

        $this->assertTrue($ecdsa->verify($public_key, $data, $signature));
    }

    public function testHS512Verify()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            'y' => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            'd' => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
        ]);

        $ecdsa = new ES512();
        $data = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = 'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn';

        $sign = $ecdsa->sign($key, $data);

        $this->assertTrue($ecdsa->verify($key, $data, $sign));
        $this->assertTrue($ecdsa->verify($key, $data, Base64Url::decode($signature)));
    }

    public function testHS512SignVerify()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => 'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
            'y' => 'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
            'd' => 'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C',
        ]);

        $ecdsa = new ES512();

        $data = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = $ecdsa->sign($key, $data);

        $this->assertTrue($ecdsa->verify($key, $data, $signature));
    }

    public function testBadSignature()
    {
        $key = new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ]);

        $ecdsa = new ES256();

        $data = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
        $signature = 'DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3';

        $this->assertFalse($ecdsa->verify($key, $data, Base64Url::decode($signature)));
    }
}
