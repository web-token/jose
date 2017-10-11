<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWKFactory;
use Jose\Object\JWK;
use Jose\Test\BaseTestCase;

/**
 * @group NoneKeys
 * @group Unit
 */
class NoneKeysBaseTest extends BaseTestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc7638#section-3.1
     */
    public function testKeyThumbprint()
    {
        $key = new JWK([
            'kty' => 'none',
            'alg' => 'none',
            'use' => 'sig',
            'kid' => '2011-04-29',
        ]);

        self::assertEquals('{"kty":"none","alg":"none","use":"sig","kid":"2011-04-29"}', json_encode($key));
        self::assertEquals('BC69Ls25CLRh1KQrXvQAAB22oyuW3eQabDSMdv9xMNk', $key->thumbprint('sha256'));
        self::assertEquals('hCnBo6v87V-Gz5Bp7eoFTrdvkGA', $key->thumbprint('sha1'));
        self::assertEquals('JI3gujreJtPt2gzxlbGnLQ', $key->thumbprint('md5'));
    }

    public function testCreateNoneKey()
    {
        $key = JWKFactory::createNoneKey(['kid' => 'NONE_KEY']);

        self::assertEquals('none', $key->get('kty'));
        self::assertEquals('none', $key->get('alg'));
        self::assertEquals('sig', $key->get('use'));
        self::assertEquals('NONE_KEY', $key->get('kid'));

        self::assertEquals('BC69Ls25CLRh1KQrXvQAAB22oyuW3eQabDSMdv9xMNk', $key->thumbprint('sha256'));
        self::assertEquals('hCnBo6v87V-Gz5Bp7eoFTrdvkGA', $key->thumbprint('sha1'));
        self::assertEquals('JI3gujreJtPt2gzxlbGnLQ', $key->thumbprint('md5'));
    }

    public function testCreateNoneKey2()
    {
        $key = JWKFactory::createKey(['kty' => 'none', 'kid' => 'NONE_KEY']);

        self::assertEquals('none', $key->get('kty'));
        self::assertEquals('none', $key->get('alg'));
        self::assertEquals('sig', $key->get('use'));
        self::assertEquals('NONE_KEY', $key->get('kid'));

        self::assertEquals('BC69Ls25CLRh1KQrXvQAAB22oyuW3eQabDSMdv9xMNk', $key->thumbprint('sha256'));
        self::assertEquals('hCnBo6v87V-Gz5Bp7eoFTrdvkGA', $key->thumbprint('sha1'));
        self::assertEquals('JI3gujreJtPt2gzxlbGnLQ', $key->thumbprint('md5'));
    }
}
