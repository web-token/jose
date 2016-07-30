<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Util;

use Assert\Assertion;
use Jose\KeyConverter\RSAKey;

final class RSA
{
    /**
     * Integer-to-Octet-String primitive.
     *
     * @param \Jose\Util\BigInteger $x
     * @param int                   $xLen
     *
     * @return string
     */
    private static function convertIntegerToOctetString($x, $xLen)
    {
        $x = $x->toBytes();
        if (strlen($x) > $xLen) {
            return false;
        }

        return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
    }

    /**
     * Octet-String-to-Integer primitive.
     *
     * @param string $x
     *
     * @return \Jose\Util\BigInteger
     */
    private static function convertOctetStringToInteger($x)
    {
        return BigInteger::createFromBinaryString($x);
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param \Jose\Util\BigInteger     $x
     *
     * @return \Jose\Util\BigInteger
     */
    private static function _exponentiate(RSAKey $key, $x)
    {
        return $x->modPow($key->getExponent(), $key->getModulus());
    }

    /**
     * RSAEP.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param \Jose\Util\BigInteger     $m
     *
     * @return \Jose\Util\BigInteger|false
     */
    private static function _rsaep(RSAKey $key, BigInteger $m)
    {
        if ($m->compare(BigInteger::createFromDecimalString('0')) < 0 || $m->compare($key->getModulus()) > 0) {
            return false;
        }

        return self::_exponentiate($key, $m);
    }

    /**
     * RSADP.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param \Jose\Util\BigInteger     $c
     *
     * @return \Jose\Util\BigInteger|false
     */
    private static function _rsadp(RSAKey $key, BigInteger $c)
    {
        if ($c->compare(BigInteger::createFromDecimalString('0')) < 0 || $c->compare($key->getModulus()) > 0) {
            return false;
        }

        return self::_exponentiate($key, $c);
    }

    /**
     * RSASP1.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param \Jose\Util\BigInteger     $m
     *
     * @return \Jose\Util\BigInteger|false
     */
    private static function _rsasp1(RSAKey $key, BigInteger $m)
    {
        if ($m->compare(BigInteger::createFromDecimalString('0')) < 0 || $m->compare($key->getModulus()) > 0) {
            return false;
        }

        return self::_exponentiate($key, $m);
    }

    /**
     * RSAVP1.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param \Jose\Util\BigInteger     $s
     *
     * @return \Jose\Util\BigInteger|false
     */
    private static function _rsavp1(RSAKey $key, BigInteger $s)
    {
        if ($s->compare(BigInteger::createFromDecimalString('0')) < 0 || $s->compare($key->getModulus()) > 0) {
            return false;
        }

        return self::_exponentiate($key, $s);
    }

    /**
     * MGF1.
     *
     * @param string          $mgfSeed
     * @param int             $maskLen
     * @param \Jose\Util\Hash $mgfHash
     *
     * @return string
     */
    private static function _mgf1($mgfSeed, $maskLen, Hash $mgfHash)
    {
        $t = '';
        $count = ceil($maskLen / $mgfHash->getLength());
        for ($i = 0; $i < $count; $i++) {
            $c = pack('N', $i);
            $t .= $mgfHash->hash($mgfSeed.$c);
        }

        return substr($t, 0, $maskLen);
    }

    /**
     * RSAES-OAEP-ENCRYPT.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param string                    $m
     * @param \Jose\Util\Hash           $hash
     *
     * @return string
     */
    private static function _rsaes_oaep_encrypt(RSAKey $key, $m, Hash $hash)
    {
        $mLen = strlen($m);
        $lHash = $hash->hash('');
        $ps = str_repeat(chr(0), $key->getModulusLength() - $mLen - 2 * $hash->getLength() - 2);
        $db = $lHash.$ps.chr(1).$m;
        $seed = random_bytes($hash->getLength());
        $dbMask = self::_mgf1($seed, $key->getModulusLength() - $hash->getLength() - 1, $hash/*MGF*/);
        $maskedDB = $db ^ $dbMask;
        $seedMask = self::_mgf1($maskedDB, $hash->getLength(), $hash/*MGF*/);
        $maskedSeed = $seed ^ $seedMask;
        $em = chr(0).$maskedSeed.$maskedDB;

        $m = self::convertOctetStringToInteger($em);
        $c = self::_rsaep($key, $m);
        $c = self::convertIntegerToOctetString($c, $key->getModulusLength());

        return $c;
    }

    /**
     * RSAES-OAEP-DECRYPT.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param string                    $c
     * @param \Jose\Util\Hash           $hash
     *
     * @return string
     */
    private static function _rsaes_oaep_decrypt(RSAKey $key, $c, Hash $hash)
    {
        $c = self::convertOctetStringToInteger($c);
        $m = self::_rsadp($key, $c);

        Assertion::isInstanceOf($m, BigInteger::class);

        $em = self::convertIntegerToOctetString($m, $key->getModulusLength());

        $lHash = $hash->hash('');
        $maskedSeed = substr($em, 1, $hash->getLength());
        $maskedDB = substr($em, $hash->getLength() + 1);
        $seedMask = self::_mgf1($maskedDB, $hash->getLength(), $hash/*MGF*/);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = self::_mgf1($seed, $key->getModulusLength() - $hash->getLength() - 1, $hash/*MGF*/);
        $db = $maskedDB ^ $dbMask;
        $lHash2 = substr($db, 0, $hash->getLength());
        $m = substr($db, $hash->getLength());

        Assertion::eq($lHash, $lHash2);

        $m = ltrim($m, chr(0));

        Assertion::eq(ord($m[0]), 1);

        return substr($m, 1);
    }

    /**
     * EMSA-PSS-ENCODE.
     *
     * @param string          $m
     * @param int             $emBits
     * @param \Jose\Util\Hash $hash
     *
     * @return string|bool
     */
    private static function _emsa_pss_encode($m, $emBits, Hash $hash)
    {
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 1) >> 3; // ie. ceil($emBits / 8)
        $sLen = $hash->getLength();

        $mHash = $hash->hash($m);
        if ($emLen < $hash->getLength() + $sLen + 2) {
            return false;
        }

        $salt = random_bytes($sLen);
        $m2 = "\0\0\0\0\0\0\0\0".$mHash.$salt;
        $h = $hash->hash($m2);
        $ps = str_repeat(chr(0), $emLen - $sLen - $hash->getLength() - 2);
        $db = $ps.chr(1).$salt;
        $dbMask = self::_mgf1($h, $emLen - $hash->getLength() - 1, $hash/*MGF*/);
        $maskedDB = $db ^ $dbMask;
        $maskedDB[0] = ~chr(0xFF << ($emBits & 7)) & $maskedDB[0];
        $em = $maskedDB.$h.chr(0xBC);

        return $em;
    }

    /**
     * EMSA-PSS-VERIFY.
     *
     * @param string                    $m
     * @param string                    $em
     * @param int                       $emBits
     * @param \Jose\Util\Hash           $hash
     *
     * @return string
     */
    private static function _emsa_pss_verify($m, $em, $emBits, Hash $hash)
    {
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 1) >> 3; // ie. ceil($emBits / 8);
        $sLen = $hash->getLength();

        $mHash = $hash->hash($m);
        if ($emLen < $hash->getLength() + $sLen + 2) {
            return false;
        }

        if ($em[strlen($em) - 1] != chr(0xBC)) {
            return false;
        }

        $maskedDB = substr($em, 0, -$hash->getLength() - 1);
        $h = substr($em, -$hash->getLength() - 1, $hash->getLength());
        $temp = chr(0xFF << ($emBits & 7));
        if ((~$maskedDB[0] & $temp) != $temp) {
            return false;
        }
        $dbMask = self::_mgf1($h, $emLen - $hash->getLength() - 1, $hash/*MGF*/);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~chr(0xFF << ($emBits & 7)) & $db[0];
        $temp = $emLen - $hash->getLength() - $sLen - 2;
        if (substr($db, 0, $temp) != str_repeat(chr(0), $temp) || ord($db[$temp]) != 1) {
            return false;
        }
        $salt = substr($db, $temp + 1); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0".$mHash.$salt;
        $h2 = $hash->hash($m2);

        return hash_equals($h, $h2);
    }

    /**
     * Encryption.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param string                    $plaintext
     * @param string                    $hash_algorithm
     *
     * @return string
     */
    public static function encrypt(RSAKey $key, $plaintext, $hash_algorithm)
    {
        $hash = Hash::$hash_algorithm();
        $length = $key->getModulusLength() - 2 * $hash->getLength() - 2;

        Assertion::greaterThan($length, 0);

        $plaintext = str_split($plaintext, $length);
        $ciphertext = '';
        foreach ($plaintext as $m) {
            $ciphertext .= self::_rsaes_oaep_encrypt($key, $m, $hash);
        }

        return $ciphertext;
    }

    /**
     * Decryption.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param string                    $ciphertext
     * @param string                    $hash_algorithm
     *
     * @return string
     */
    public static function decrypt(RSAKey $key, $ciphertext, $hash_algorithm)
    {
        Assertion::greaterThan($key->getModulusLength(), 0);

        $hash = Hash::$hash_algorithm();

        $ciphertext = str_split($ciphertext, $key->getModulusLength());
        $ciphertext[count($ciphertext) - 1] = str_pad($ciphertext[count($ciphertext) - 1], $key->getModulusLength(), chr(0), STR_PAD_LEFT);

        $plaintext = '';

        foreach ($ciphertext as $c) {
            $temp = self::_rsaes_oaep_decrypt($key, $c, $hash);
            if ($temp === false) {
                return false;
            }
            $plaintext .= $temp;
        }

        return $plaintext;
    }

    /**
     * Create a signature.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param string                    $message
     * @param string                    $hash
     *
     * @return string
     */
    public static function sign(RSAKey $key, $message, $hash)
    {
        Assertion::string($message);
        Assertion::string($hash);
        Assertion::inArray($hash, ['sha256', 'sha384', 'sha512']);

        $em = self::_emsa_pss_encode($message, 8 * $key->getModulusLength() - 1, Hash::$hash());

        Assertion::string($em);

        $message = self::convertOctetStringToInteger($em);
        $signature = self::_rsasp1($key, $message);

        Assertion::isInstanceOf($signature, BigInteger::class);

        $signature = self::convertIntegerToOctetString($signature, $key->getModulusLength());

        return $signature;
    }

    /**
     * Verifies a signature.
     *
     * @param \Jose\KeyConverter\RSAKey $key
     * @param string                    $message
     * @param string                    $signature
     * @param string                    $hash
     *
     * @return bool
     */
    public static function verify(RSAKey $key, $message, $signature, $hash)
    {
        Assertion::string($message);
        Assertion::string($signature);
        Assertion::string($hash);
        Assertion::inArray($hash, ['sha256', 'sha384', 'sha512']);
        Assertion::eq(strlen($signature), $key->getModulusLength());

        $modBits = 8 * $key->getModulusLength();

        $s2 = self::convertOctetStringToInteger($signature);
        $m2 = self::_rsavp1($key, $s2);

        Assertion::isInstanceOf($m2, BigInteger::class);

        $em = self::convertIntegerToOctetString($m2, $modBits >> 3);

        return self::_emsa_pss_verify($message, $em, $modBits - 1, Hash::$hash());
    }
}
