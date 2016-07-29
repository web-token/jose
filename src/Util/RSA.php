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

final class RSA
{
    /**
     * ASN1 Integer.
     */
    const ASN1_INTEGER = 2;

    /**
     * ASN1 Bit String.
     */
    const ASN1_BITSTRING = 3;

    /**
     * ASN1 Octet String.
     */
    const ASN1_OCTETSTRING = 4;

    /**
     * ASN1 Object Identifier.
     */
    const ASN1_OBJECT = 6;

    /**
     * ASN1 Sequence (with the constucted bit set).
     */
    const ASN1_SEQUENCE = 48;

    /**
     * To use the pure-PHP implementation.
     */
    const MODE_INTERNAL = 1;

    /**
     * To use the OpenSSL library.
     */
    const MODE_OPENSSL = 2;

    /**
     * PKCS#1 formatted private key.
     */
    const PRIVATE_FORMAT_PKCS1 = 0;

    /**
     * PuTTY formatted private key.
     */
    const PRIVATE_FORMAT_PUTTY = 1;

    /**
     * XML formatted private key.
     */
    const PRIVATE_FORMAT_XML = 2;

    /**
     * PKCS#8 formatted private key.
     */
    const PRIVATE_FORMAT_PKCS8 = 8;

    /**
     * Raw public key.
     */
    const PUBLIC_FORMAT_RAW = 3;

    /**
     * PKCS#1 formatted public key (raw).
     */
    const PUBLIC_FORMAT_PKCS1 = 4;

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
     * @var array
     */
    private $primes = [];

    /**
     * Exponents for Chinese Remainder Theorem (ie. dP and dQ).
     *
     * @var array
     */
    private $exponents = [];

    /**
     * Coefficients for Chinese Remainder Theorem (ie. qInv).
     *
     * @var array
     */
    private $coefficients = [];

    /**
     * Hash function.
     *
     * @var \Jose\Util\Hash
     */
    private $hash;

    /**
     * Length of salt.
     *
     * @var int
     */
    private $sLen;

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
     * Break a public or private key down into its constituant components.
     *
     * @param string $key
     * @param int    $type
     *
     * @return array
     */
    private function _parseKey($key, $type)
    {
        Assertion::string($key);

        $decoded = $this->_extractBER($key);

        if ($decoded !== false) {
            $key = $decoded;
        }

        $components = [];

        if (ord($this->_string_shift($key)) != self::ASN1_SEQUENCE) {
            return false;
        }
        if ($this->_decodeLength($key) != strlen($key)) {
            return false;
        }

        $tag = ord($this->_string_shift($key));

        if ($tag == self::ASN1_INTEGER && substr($key, 0, 3) == "\x01\x00\x30") {
            $this->_string_shift($key, 3);
            $tag = self::ASN1_SEQUENCE;
        }

        if ($tag == self::ASN1_SEQUENCE) {
            $temp = $this->_string_shift($key, $this->_decodeLength($key));
            if (ord($this->_string_shift($temp)) != self::ASN1_OBJECT) {
                return false;
            }
            $length = $this->_decodeLength($temp);
            switch ($this->_string_shift($temp, $length)) {
                case "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01": // rsaEncryption
                    break;
            }
            $tag = ord($this->_string_shift($key)); // skip over the BIT STRING / OCTET STRING tag
            $this->_decodeLength($key); // skip over the BIT STRING / OCTET STRING length
            if ($tag == self::ASN1_BITSTRING) {
                $this->_string_shift($key);
            }
            if (ord($this->_string_shift($key)) != self::ASN1_SEQUENCE) {
                return false;
            }
            if ($this->_decodeLength($key) != strlen($key)) {
                return false;
            }
            $tag = ord($this->_string_shift($key));
        }
        if ($tag != self::ASN1_INTEGER) {
            return false;
        }

        $length = $this->_decodeLength($key);
        $temp = $this->_string_shift($key, $length);
        if (strlen($temp) != 1 || ord($temp) > 2) {
            $components['modulus'] = BigInteger::createFromBinaryString($temp);
            $this->_string_shift($key); // skip over self::ASN1_INTEGER
            $length = $this->_decodeLength($key);
            $components[$type == self::PUBLIC_FORMAT_PKCS1 ? 'publicExponent' : 'privateExponent'] = BigInteger::createFromBinaryString($this->_string_shift($key, $length));

            return $components;
        }
        if (ord($this->_string_shift($key)) != self::ASN1_INTEGER) {
            return false;
        }
        $length = $this->_decodeLength($key);
        $components['modulus'] = BigInteger::createFromBinaryString($this->_string_shift($key, $length));
        $this->_string_shift($key);
        $length = $this->_decodeLength($key);
        $components['publicExponent'] = BigInteger::createFromBinaryString($this->_string_shift($key, $length));
        $this->_string_shift($key);
        $length = $this->_decodeLength($key);
        $components['privateExponent'] = BigInteger::createFromBinaryString($this->_string_shift($key, $length));
        $this->_string_shift($key);
        $length = $this->_decodeLength($key);
        $components['primes'] = [1 => BigInteger::createFromBinaryString($this->_string_shift($key, $length))];
        $this->_string_shift($key);
        $length = $this->_decodeLength($key);
        $components['primes'][] = BigInteger::createFromBinaryString($this->_string_shift($key, $length));
        $this->_string_shift($key);
        $length = $this->_decodeLength($key);
        $components['exponents'] = [1 => BigInteger::createFromBinaryString($this->_string_shift($key, $length))];
        $this->_string_shift($key);
        $length = $this->_decodeLength($key);
        $components['exponents'][] = BigInteger::createFromBinaryString($this->_string_shift($key, $length));
        $this->_string_shift($key);
        $length = $this->_decodeLength($key);
        $components['coefficients'] = [2 => BigInteger::createFromBinaryString($this->_string_shift($key, $length))];

        return $components;
    }

    /**
     * Loads a public or private key.
     *
     * @param string $key
     * @param bool   $type optional
     *
     * @return bool
     */
    public function loadKey($key, $type = false)
    {
        $components = $this->_parseKey($key, $type);

        if ($components === false) {
            return false;
        }

        $this->modulus = $components['modulus'];
        $this->k = strlen($this->modulus->toBytes());
        $this->exponent = isset($components['privateExponent']) ? $components['privateExponent'] : $components['publicExponent'];
        if (isset($components['primes'])) {
            $this->primes = $components['primes'];
            $this->exponents = $components['exponents'];
            $this->coefficients = $components['coefficients'];
            $this->publicExponent = $components['publicExponent'];
        } else {
            $this->primes = [];
            $this->exponents = [];
            $this->coefficients = [];
            $this->publicExponent = false;
        }

        switch (true) {
            case strpos($key, '-BEGIN PUBLIC KEY-') !== false:
            case strpos($key, '-BEGIN RSA PUBLIC KEY-') !== false:
                $this->setPublicKey();
        }

        return true;
    }

    /**
     * DER-decode the length.
     *
     * @param string $string
     *
     * @return int
     */
    private function _decodeLength(&$string)
    {
        $length = ord($this->_string_shift($string));
        if ($length & 0x80) { // definite length, long form
            $length &= 0x7F;
            $temp = $this->_string_shift($string, $length);
            list(, $length) = unpack('N', substr(str_pad($temp, 4, chr(0), STR_PAD_LEFT), -4));
        }

        return $length;
    }

    /**
     * String Shift.
     *
     * @param string $string
     * @param int    $index
     *
     * @return string
     */
    private function _string_shift(&$string, $index = 1)
    {
        $substr = substr($string, 0, $index);
        $string = substr($string, $index);

        return $substr;
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
     * Determines the salt length.
     *
     * @param int $sLen
     */
    public function setSaltLength($sLen)
    {
        $this->sLen = $sLen;
    }

    /**
     * Integer-to-Octet-String primitive.
     *
     * @param \Jose\Util\BigInteger $x
     * @param int                   $xLen
     *
     * @return string
     */
    private function _i2osp($x, $xLen)
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
    private function _os2ip($x)
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
     * @return \Jose\Util\BigInteger
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
     * @return \Jose\Util\BigInteger
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
     * @return \Jose\Util\BigInteger
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
     * @return \Jose\Util\BigInteger
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

        $m = $this->_os2ip($em);
        $c = $this->_rsaep($m);
        $c = $this->_i2osp($c, $this->k);

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

        $c = $this->_os2ip($c);
        $m = $this->_rsadp($c);
        if ($m === false) {

            return false;
        }
        $em = $this->_i2osp($m, $this->k);

        // EME-OAEP decoding

        $lHash = $this->hash->hash($l);
        $y = ord($em[0]);
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
        $sLen = $this->sLen ? $this->sLen : $this->hash->getLength();

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
        $sLen = $this->sLen ? $this->sLen : $this->hash->getLength();

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

        $m = $this->_os2ip($em);
        $s = $this->_rsasp1($m);
        $s = $this->_i2osp($s, $this->k);

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

        $s2 = $this->_os2ip($s);
        $m2 = $this->_rsavp1($s2);
        if ($m2 === false) {

            return false;
        }
        $em = $this->_i2osp($m2, $modBits >> 3);
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

    /**
     * Extract raw BER from Base64 encoding.
     *
     * @param string $str
     *
     * @return string
     */
    private function _extractBER($str)
    {
        $temp = preg_replace('#.*?^-+[^-]+-+[\r\n ]*$#ms', '', $str, 1);
        // remove the -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- stuff
        $temp = preg_replace('#-+[^-]+-+#', '', $temp);
        // remove new lines
        $temp = str_replace(["\r", "\n", ' '], '', $temp);
        $temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? base64_decode($temp) : false;

        return $temp != false ? $temp : $str;
    }

    /**
     * Defines the public key.
     *
     * @return bool
     */
    private function setPublicKey()
    {
        if (!empty($this->modulus)) {
            $this->publicExponent = $this->exponent;

            return true;
        }
    }
}
