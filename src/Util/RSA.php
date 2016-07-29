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

use Base64Url\Base64Url;
use Jose\Object\JWKInterface;

final class RSA
{
    /**
     * Precomputed Zero.
     *
     * @var \Jose\Util\BigInteger
     */
    private $zero;

    /**
     * Precomputed One.
     *
     * @var \Jose\Util\BigInteger
     */
    private $one;

    /**
     * Modulus (ie. n).
     *
     * @var \Jose\Util\BigInteger
     */
    private $modulus;

    /**
     * Modulus length.
     *
     * @var int
     */
    private $k;

    /**
     * Exponent (ie. e or d).
     *
     * @var \Jose\Util\BigInteger
     */
    private $exponent;

    /**
     * Primes for Chinese Remainder Theorem (ie. p and q).
     *
     * @var \Jose\Util\BigInteger[]
     */
    private $primes;

    /**
     * Exponents for Chinese Remainder Theorem (ie. dP and dQ).
     *
     * @var \Jose\Util\BigInteger[]
     */
    private $exponents;

    /**
     * Coefficients for Chinese Remainder Theorem (ie. qInv).
     *
     * @var \Jose\Util\BigInteger[]
     */
    private $coefficients;

    /**
     * Hash function.
     *
     * @var \Jose\Util\Hash
     */
    private $hash;

    /**
     * Hash function for the Mask Generation Function.
     *
     * @var \Jose\Util\Hash
     */
    private $mgfHash;

    /**
     * Public Exponent.
     *
     * @var mixed
     */
    private $publicExponent = false;

    /**
     * RSA constructor.
     */
    public function __construct()
    {
        $this->zero = BigInteger::createFromDecimalString('0');
        $this->one = BigInteger::createFromDecimalString('1');

        $this->hash = Hash::sha1();
        $this->mgfHash = Hash::sha1();
    }

    /**
     * Loads a public or private key.
     *
     * @param \Jose\Object\JWKInterface $key
     */
    public function loadKey(JWKInterface $key)
    {
        $this->modulus = BigInteger::createFromBinaryString(Base64Url::decode($key->get('n')));
        $this->k = strlen($this->modulus->toBytes());

        if ($key->has('d')) {
            $this->exponent = BigInteger::createFromBinaryString(Base64Url::decode($key->get('d')));
            $this->publicExponent = BigInteger::createFromBinaryString(Base64Url::decode($key->get('e')));
        } else {
            $this->exponent = BigInteger::createFromBinaryString(Base64Url::decode($key->get('e')));
        }

        if ($key->has('p') && $key->has('q')) {
            $this->primes = [
                BigInteger::createFromBinaryString(Base64Url::decode($key->get('p'))),
                BigInteger::createFromBinaryString(Base64Url::decode($key->get('q'))),
            ];
        } else {
            $this->primes = [];
        }

        if ($key->has('dp') && $key->has('dq') && $key->has('qi')) {
            $this->coefficients = [
                BigInteger::createFromBinaryString(Base64Url::decode($key->get('dp'))),
                BigInteger::createFromBinaryString(Base64Url::decode($key->get('dq'))),
                BigInteger::createFromBinaryString(Base64Url::decode($key->get('qi'))),
            ];
        } else {
            $this->coefficients = [];
        }
    }

    /**
     * Determines which hashing function should be used.
     *
     * @param string $hash
     */
    public function setHash($hash)
    {
        $this->hash = Hash::$hash();
    }

    /**
     * Determines which hashing function should be used for the mask generation function.
     *
     * @param string $hash
     */
    public function setMGFHash($hash)
    {
        $this->mgfHash = Hash::$hash();
    }

    /**
     * Integer-to-Octet-String primitive.
     *
     * @param \Jose\Util\BigInteger $x
     * @param int                   $xLen
     *
     * @return string
     */
    private function convertIntegerToOctetString($x, $xLen)
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
    private function convertOctetStringToInteger($x)
    {
        return BigInteger::createFromBinaryString($x);
    }

    /**
     * Exponentiate with or without Chinese Remainder Theorem.
     *
     * @param \Jose\Util\BigInteger $x
     *
     * @return \Jose\Util\BigInteger
     */
    private function _exponentiate($x)
    {
        if (empty($this->primes) || empty($this->coefficients) || empty($this->exponents)) {
            return $x->modPow($this->exponent, $this->modulus);
        }

        $num_primes = count($this->primes);

        $smallest = $this->primes[1];
        for ($i = 2; $i <= $num_primes; $i++) {
            if ($smallest->compare($this->primes[$i]) > 0) {
                $smallest = $this->primes[$i];
            }
        }

        $one = BigInteger::createFromDecimalString('1');

        $r = $one->random($one, $smallest->subtract($one));

        $m_i = [
            1 => $this->_blind($x, $r, 1),
            2 => $this->_blind($x, $r, 2),
        ];
        $h = $m_i[1]->subtract($m_i[2]);
        $h = $h->multiply($this->coefficients[2]);
        list(, $h) = $h->divide($this->primes[1]);
        $m = $m_i[2]->add($h->multiply($this->primes[2]));

        $r = $this->primes[1];
        for ($i = 3; $i <= $num_primes; $i++) {
            $m_i = $this->_blind($x, $r, $i);

            $r = $r->multiply($this->primes[$i - 1]);

            $h = $m_i->subtract($m);
            $h = $h->multiply($this->coefficients[$i]);
            list(, $h) = $h->divide($this->primes[$i]);

            $m = $m->add($r->multiply($h));
        }

        return $m;
    }

    /**
     * Performs RSA Blinding.
     *
     * @param \Jose\Util\BigInteger $x
     * @param \Jose\Util\BigInteger $r
     * @param int                   $i
     *
     * @return \Jose\Util\BigInteger
     */
    private function _blind($x, $r, $i)
    {
        $x = $x->multiply($r->modPow($this->publicExponent, $this->primes[$i]));
        $x = $x->modPow($this->exponents[$i], $this->primes[$i]);

        $r = $r->modInverse($this->primes[$i]);
        $x = $x->multiply($r);
        list(, $x) = $x->divide($this->primes[$i]);

        return $x;
    }

    /**
     * Performs blinded RSA equality testing.
     *
     * @param string $x
     * @param string $y
     *
     * @return bool
     */
    private function _equals($x, $y)
    {
        if (strlen($x) != strlen($y)) {
            return false;
        }

        $result = 0;
        for ($i = 0; $i < strlen($x); $i++) {
            $result |= ord($x[$i]) ^ ord($y[$i]);
        }

        return $result == 0;
    }

    /**
     * RSAEP.
     *
     * @param \Jose\Util\BigInteger $m
     *
     * @return \Jose\Util\BigInteger|false
     */
    private function _rsaep($m)
    {
        if ($m->compare($this->zero) < 0 || $m->compare($this->modulus) > 0) {

            return false;
        }

        return $this->_exponentiate($m);
    }

    /**
     * RSADP.
     *
     * @param \Jose\Util\BigInteger $c
     *
     * @return \Jose\Util\BigInteger|false
     */
    private function _rsadp($c)
    {
        if ($c->compare($this->zero) < 0 || $c->compare($this->modulus) > 0) {

            return false;
        }

        return $this->_exponentiate($c);
    }

    /**
     * RSASP1.
     *
     * @param \Jose\Util\BigInteger $m
     *
     * @return \Jose\Util\BigInteger|false
     */
    private function _rsasp1($m)
    {
        if ($m->compare($this->zero) < 0 || $m->compare($this->modulus) > 0) {

            return false;
        }

        return $this->_exponentiate($m);
    }

    /**
     * RSAVP1.
     *
     * @param \Jose\Util\BigInteger $s
     *
     * @return \Jose\Util\BigInteger|false
     */
    private function _rsavp1($s)
    {
        if ($s->compare($this->zero) < 0 || $s->compare($this->modulus) > 0) {

            return false;
        }

        return $this->_exponentiate($s);
    }

    /**
     * MGF1.
     *
     * @param string $mgfSeed
     * @param int    $maskLen
     *
     * @return string
     */
    private function _mgf1($mgfSeed, $maskLen)
    {
        // if $maskLen would yield strings larger than 4GB, PKCS#1 suggests a "Mask too long" error be output.

        $t = '';
        $count = ceil($maskLen / $this->mgfHash->getLength());
        for ($i = 0; $i < $count; $i++) {
            $c = pack('N', $i);
            $t .= $this->mgfHash->hash($mgfSeed.$c);
        }

        return substr($t, 0, $maskLen);
    }

    /**
     * RSAES-OAEP-ENCRYPT.
     *
     * @param string $m
     * @param string $l
     *
     * @return string
     */
    private function _rsaes_oaep_encrypt($m, $l = '')
    {
        $mLen = strlen($m);

        // Length checking

        // if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        if ($mLen > $this->k - 2 * $this->hash->getLength() - 2) {

            return false;
        }

        // EME-OAEP encoding

        $lHash = $this->hash->hash($l);
        $ps = str_repeat(chr(0), $this->k - $mLen - 2 * $this->hash->getLength() - 2);
        $db = $lHash.$ps.chr(1).$m;
        $seed = random_bytes($this->hash->getLength());
        $dbMask = $this->_mgf1($seed, $this->k - $this->hash->getLength() - 1);
        $maskedDB = $db ^ $dbMask;
        $seedMask = $this->_mgf1($maskedDB, $this->hash->getLength());
        $maskedSeed = $seed ^ $seedMask;
        $em = chr(0).$maskedSeed.$maskedDB;

        // RSA encryption

        $m = $this->convertOctetStringToInteger($em);
        $c = $this->_rsaep($m);
        $c = $this->convertIntegerToOctetString($c, $this->k);

        // Output the ciphertext C

        return $c;
    }

    /**
     * RSAES-OAEP-DECRYPT.
     *
     * @param string $c
     * @param string $l
     *
     * @return string
     */
    private function _rsaes_oaep_decrypt($c, $l = '')
    {
        // Length checking

        // if $l is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        if (strlen($c) != $this->k || $this->k < 2 * $this->hash->getLength() + 2) {

            return false;
        }

        // RSA decryption

        $c = $this->convertOctetStringToInteger($c);
        $m = $this->_rsadp($c);
        if ($m === false) {

            return false;
        }
        $em = $this->convertIntegerToOctetString($m, $this->k);

        // EME-OAEP decoding

        $lHash = $this->hash->hash($l);
        $maskedSeed = substr($em, 1, $this->hash->getLength());
        $maskedDB = substr($em, $this->hash->getLength() + 1);
        $seedMask = $this->_mgf1($maskedDB, $this->hash->getLength());
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = $this->_mgf1($seed, $this->k - $this->hash->getLength() - 1);
        $db = $maskedDB ^ $dbMask;
        $lHash2 = substr($db, 0, $this->hash->getLength());
        $m = substr($db, $this->hash->getLength());
        if ($lHash != $lHash2) {

            return false;
        }
        $m = ltrim($m, chr(0));
        if (ord($m[0]) != 1) {

            return false;
        }

        // Output the message M

        return substr($m, 1);
    }

    /**
     * EMSA-PSS-ENCODE.
     *
     * @param string $m
     * @param int    $emBits
     *
     * @return bool
     */
    private function _emsa_pss_encode($m, $emBits)
    {
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 1) >> 3; // ie. ceil($emBits / 8)
        $sLen = $this->hash->getLength();

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hash->getLength() + $sLen + 2) {

            return false;
        }

        $salt = random_bytes($sLen);
        $m2 = "\0\0\0\0\0\0\0\0".$mHash.$salt;
        $h = $this->hash->hash($m2);
        $ps = str_repeat(chr(0), $emLen - $sLen - $this->hash->getLength() - 2);
        $db = $ps.chr(1).$salt;
        $dbMask = $this->_mgf1($h, $emLen - $this->hash->getLength() - 1);
        $maskedDB = $db ^ $dbMask;
        $maskedDB[0] = ~chr(0xFF << ($emBits & 7)) & $maskedDB[0];
        $em = $maskedDB.$h.chr(0xBC);

        return $em;
    }

    /**
     * EMSA-PSS-VERIFY.
     *
     * @param string $m
     * @param string $em
     * @param int    $emBits
     *
     * @return string
     */
    private function _emsa_pss_verify($m, $em, $emBits)
    {
        // if $m is larger than two million terrabytes and you're using sha1, PKCS#1 suggests a "Label too long" error
        // be output.

        $emLen = ($emBits + 1) >> 3; // ie. ceil($emBits / 8);
        $sLen = $this->hash->getLength();

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hash->getLength() + $sLen + 2) {
            return false;
        }

        if ($em[strlen($em) - 1] != chr(0xBC)) {
            return false;
        }

        $maskedDB = substr($em, 0, -$this->hash->getLength() - 1);
        $h = substr($em, -$this->hash->getLength() - 1, $this->hash->getLength());
        $temp = chr(0xFF << ($emBits & 7));
        if ((~$maskedDB[0] & $temp) != $temp) {
            return false;
        }
        $dbMask = $this->_mgf1($h, $emLen - $this->hash->getLength() - 1);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~chr(0xFF << ($emBits & 7)) & $db[0];
        $temp = $emLen - $this->hash->getLength() - $sLen - 2;
        if (substr($db, 0, $temp) != str_repeat(chr(0), $temp) || ord($db[$temp]) != 1) {
            return false;
        }
        $salt = substr($db, $temp + 1); // should be $sLen long
        $m2 = "\0\0\0\0\0\0\0\0".$mHash.$salt;
        $h2 = $this->hash->hash($m2);

        return $this->_equals($h, $h2);
    }

    /**
     * RSASSA-PSS-SIGN.
     *
     * @param string $m
     *
     * @return string
     */
    private function _rsassa_pss_sign($m)
    {
        // EMSA-PSS encoding

        $em = $this->_emsa_pss_encode($m, 8 * $this->k - 1);

        // RSA signature

        $m = $this->convertOctetStringToInteger($em);
        $s = $this->_rsasp1($m);
        $s = $this->convertIntegerToOctetString($s, $this->k);

        // Output the signature S

        return $s;
    }

    /**
     * RSASSA-PSS-VERIFY.
     *
     * @param string $m
     * @param string $s
     *
     * @return string
     */
    private function _rsassa_pss_verify($m, $s)
    {
        // Length checking

        if (strlen($s) != $this->k) {

            return false;
        }

        // RSA verification

        $modBits = 8 * $this->k;

        $s2 = $this->convertOctetStringToInteger($s);
        $m2 = $this->_rsavp1($s2);
        if ($m2 === false) {

            return false;
        }
        $em = $this->convertIntegerToOctetString($m2, $modBits >> 3);
        if ($em === false) {

            return false;
        }

        // EMSA-PSS verification

        return $this->_emsa_pss_verify($m, $em, $modBits - 1);
    }

    /**
     * Encryption.
     *
     * Both self::ENCRYPTION_OAEP and self::ENCRYPTION_PKCS1 both place limits on how long $plaintext can be.
     * If $plaintext exceeds those limits it will be broken up so that it does and the resultant ciphertext's will
     * be concatenated together.
     *
     * @see self::decrypt()
     *
     * @param string $plaintext
     *
     * @return string
     */
    public function encrypt($plaintext)
    {
        $length = $this->k - 2 * $this->hash->getLength() - 2;
        if ($length <= 0) {
            return false;
        }

        $plaintext = str_split($plaintext, $length);
        $ciphertext = '';
        foreach ($plaintext as $m) {
            $ciphertext .= $this->_rsaes_oaep_encrypt($m);
        }

        return $ciphertext;
    }

    /**
     * Decryption.
     *
     * @param string $ciphertext
     *
     * @return string
     */
    public function decrypt($ciphertext)
    {
        if ($this->k <= 0) {
            return false;
        }

        $ciphertext = str_split($ciphertext, $this->k);
        $ciphertext[count($ciphertext) - 1] = str_pad($ciphertext[count($ciphertext) - 1], $this->k, chr(0), STR_PAD_LEFT);

        $plaintext = '';

        foreach ($ciphertext as $c) {
            $temp = $this->_rsaes_oaep_decrypt($c);
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
     * @param string $message
     *
     * @return string
     */
    public function sign($message)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }


        return $this->_rsassa_pss_sign($message);
    }

    /**
     * Verifies a signature.
     *
     * @param string $message
     * @param string $signature
     *
     * @return bool
     */
    public function verify($message, $signature)
    {
        if (empty($this->modulus) || empty($this->exponent)) {
            return false;
        }

        return $this->_rsassa_pss_verify($message, $signature);
    }
}
