<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\KeyConverter\ECKey;
use Jose\KeyConverter\KeyConverter;
use Jose\Test\BaseTestCase;

/**
 * @group ECKeys
 * @group Unit
 */
class ECKeysBaseTest extends BaseTestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported key type
     */
    public function testKeyTypeNotSupported()
    {
        $file = 'file://'.__DIR__.DIRECTORY_SEPARATOR.'DSA'.DIRECTORY_SEPARATOR.'DSA.key';
        KeyConverter::loadFromKeyFile($file);
    }

    /**
     * @see https://github.com/Spomky-Labs/jose/issues/141
     * @see https://gist.github.com/Spomky/246eca6aaeeb7a40f11d3a2d98960282
     */
    public function testLoadPrivateEC256KeyGenerateByAPN()
    {
        $pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es256.from.APN.key');
        $details = KeyConverter::loadFromKey($pem);
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => '13n3isfsEktzl-CtH5ECpRrKk-40prVuCbldkP77gak',
            'x' => 'YcIMUkalwbeeAVkUF6FP3aBVlCzlqxEd7i0uN_4roA0',
            'y' => 'bU8wOWJBkTNZ61gB1_4xp-r8-uVsQB8D6Xsl-aKMCy8',
        ]);
    }

    public function testLoadPublicEC256Key()
    {
        $pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es256.key');
        $details = KeyConverter::loadFromKey($pem);
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]);

        $ec_key = new ECKey($details);

        self::assertEquals(str_replace("\r\n", PHP_EOL, $pem), $ec_key->toPEM());
    }

    public function testLoadPrivateEC256Key()
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es256.key');
        $public_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es256.key');
        $details = KeyConverter::loadFromKey($private_pem);
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]);

        $ec_key = new ECKey($details);

        self::assertEquals(str_replace("\r\n", PHP_EOL, $private_pem), $ec_key->toPEM());
        self::assertEquals(str_replace("\r\n", PHP_EOL, $public_pem), ECKey::toPublic($ec_key)->toPEM());
    }

    public function testLoadEncryptedPrivateEC256Key()
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es256.encrypted.key');
        $public_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es256.key');
        $details = KeyConverter::loadFromKey($private_pem, 'test');
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-256',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
        ]);

        $ec_key = new ECKey($details);
        self::assertEquals(str_replace("\r\n", PHP_EOL, $public_pem), ECKey::toPublic($ec_key)->toPEM());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Password required for encrypted keys.
     */
    public function testLoadEncryptedPrivateEC256KeyWithoutPassword()
    {
        KeyConverter::loadFromKeyFile('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es256.encrypted.key');
    }

    public function testLoadPublicEC384Key()
    {
        $pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es384.key');
        $details = KeyConverter::loadFromKey($pem);
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-384',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);

        $ec_key = new ECKey($details);

        self::assertEquals(str_replace("\r\n", PHP_EOL, $pem), $ec_key->toPEM());
    }

    public function testLoadPrivateEC384Key()
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es384.key');
        $public_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es384.key');
        $details = KeyConverter::loadFromKey($private_pem);
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-384',
            'd' => 'pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);

        $ec_key = new ECKey($details);

        self::assertEquals(str_replace("\r\n", PHP_EOL, $private_pem), $ec_key->toPEM());
        self::assertEquals(str_replace("\r\n", PHP_EOL, $public_pem), ECKey::toPublic($ec_key)->toPEM());
    }

    public function testLoadEncryptedPrivateEC384Key()
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es384.encrypted.key');
        $public_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es384.key');
        $details = KeyConverter::loadFromKey($private_pem, 'test');
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-384',
            'd' => 'pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr',
            'x' => '6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ',
            'y' => 'b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU',
        ]);
        $ec_key = new ECKey($details);

        self::assertEquals(str_replace("\r\n", PHP_EOL, $public_pem), ECKey::toPublic($ec_key)->toPEM());
    }

    public function testLoadPublicEC512Key()
    {
        $pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es512.key');
        $details = KeyConverter::loadFromKey($pem);
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-521',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);

        $ec_key = new ECKey($details);

        self::assertEquals(str_replace("\r\n", PHP_EOL, $pem), $ec_key->toPEM());
    }

    public function testLoadPrivateEC512Key()
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es512.key');
        $public_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es512.key');
        $details = KeyConverter::loadFromKey($private_pem);
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-521',
            'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);

        $ec_key = new ECKey($details);

        self::assertEquals(str_replace("\r\n", PHP_EOL, $private_pem), $ec_key->toPEM());
        self::assertEquals(str_replace("\r\n", PHP_EOL, $public_pem), ECKey::toPublic($ec_key)->toPEM());
    }

    public function testLoadEncryptedPrivateEC512Key()
    {
        $private_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'private.es512.encrypted.key');
        $public_pem = file_get_contents('file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'public.es512.key');
        $details = KeyConverter::loadFromKey($private_pem, 'test');
        self::assertEquals($details, [
            'kty' => 'EC',
            'crv' => 'P-521',
            'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);

        $ec_key = new ECKey($details);

        self::assertEquals(str_replace("\r\n", PHP_EOL, $public_pem), ECKey::toPublic($ec_key)->toPEM());
    }

    public function testConvertPrivateKeyToPublic()
    {
        $private_ec_key = new ECKey([
            'kty' => 'EC',
            'kid' => 'Foo',
            'crv' => 'P-256',
            'use' => 'sig',
            'd' => 'q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
            'foo' => 'bar',
        ]);

        $public_ec_key = ECKey::toPublic($private_ec_key);

        self::assertEquals([
            'kty' => 'EC',
            'kid' => 'Foo',
            'crv' => 'P-256',
            'use' => 'sig',
            'x' => 'vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U',
            'y' => 'oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE',
            'foo' => 'bar',
        ], $public_ec_key->toArray());
    }
}
