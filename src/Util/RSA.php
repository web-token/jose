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

final class RSA
{
    /**
     * Optimal Asymmetric Encryption Padding (OAEP).
     */
    const ENCRYPTION_OAEP = 1;

    /**
     * PKCS#1 padding.
     */
    const ENCRYPTION_PKCS1 = 2;

    /**
     * Probabilistic Signature Scheme for signing.
     */
    const SIGNATURE_PSS = 1;
    /**
     * PKCS#1 scheme.
     */
    const SIGNATURE_PKCS1 = 2;

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
    const PUBLIC_FORMAT_PKCS1_RAW = 4;

    /**
     * XML formatted public key.
     */
    const PUBLIC_FORMAT_XML = 5;

    /**
     * OpenSSH formatted public key.
     */
    const PUBLIC_FORMAT_OPENSSH = 6;

    /**
     * PKCS#1 formatted public key (encapsulated).
     */
    const PUBLIC_FORMAT_PKCS8 = 7;

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
     * Private Key Format.
     *
     * @var int
     */
    private $privateKeyFormat = self::PRIVATE_FORMAT_PKCS1;

    /**
     * Public Key Format.
     *
     * @var int
     */
    private $publicKeyFormat = self::PUBLIC_FORMAT_PKCS8;

    /**
     * Modulus (ie. n).
     *
     * @var \Jose\Util\BigInteger
     */
    private $modulus;

    /**
     * Modulus length.
     *
     * @var \Jose\Util\BigInteger
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
    private $primes;

    /**
     * Exponents for Chinese Remainder Theorem (ie. dP and dQ).
     *
     * @var array
     */
    private $exponents;

    /**
     * Coefficients for Chinese Remainder Theorem (ie. qInv).
     *
     * @var array
     */
    private $coefficients;

    /**
     * Hash name.
     *
     * @var string
     */
    private $hashName;

    /**
     * Hash function.
     *
     * @var \Jose\Util\Hash
     */
    private $hash;

    /**
     * Length of hash function output.
     *
     * @var int
     */
    private $hLen;

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
     * Length of MGF hash function output.
     *
     * @var int
     */
    private $mgfHLen;

    /**
     * Encryption mode.
     *
     * @var int
     */
    private $encryptionMode = self::ENCRYPTION_OAEP;

    /**
     * Signature mode.
     *
     * @var int
     */
    private $signatureMode = self::SIGNATURE_PSS;

    /**
     * Public Exponent.
     *
     * @var mixed
     */
    private $publicExponent = false;

    /**
     * Password.
     *
     * @var string
     */
    private $password = false;

    /**
     * Components.
     *
     * @var array
     */
    private $components = [];

    /**
     * Current String.
     *
     * @var mixed
     */
    private $current;

    /**
     * OpenSSL configuration file name.
     *
     * @var mixed
     */
    private $configFile;

    /**
     * Public key comment field.
     *
     * @var string
     */
    private $comment = 'phpseclib-generated-key';

    /**
     * RSA constructor.
     */
    public function __construct()
    {
        $this->configFile = dirname(__FILE__).'/../openssl.cnf';

        if (!defined('CRYPT_RSA_MODE')) {
            switch (true) {
                // Math/BigInteger's openssl requirements are a little less stringent than Crypt/RSA's. in particular,
                // Math/BigInteger doesn't require an openssl.cfg file whereas Crypt/RSA does. so if Math/BigInteger
                // can't use OpenSSL it can be pretty trivially assumed, then, that Crypt/RSA can't either.
                case defined('MATH_BIGINTEGER_OPENSSL_DISABLE'):
                    define('CRYPT_RSA_MODE', self::MODE_INTERNAL);
                    break;
                case extension_loaded('openssl') && file_exists($this->configFile):
                    // some versions of XAMPP have mismatched versions of OpenSSL which causes it not to work
                    ob_start();
                    @phpinfo();
                    $content = ob_get_contents();
                    ob_end_clean();

                    preg_match_all('#OpenSSL (Header|Library) Version(.*)#im', $content, $matches);

                    $versions = [];
                    if (!empty($matches[1])) {
                        for ($i = 0; $i < count($matches[1]); $i++) {
                            $fullVersion = trim(str_replace('=>', '', strip_tags($matches[2][$i])));

                            // Remove letter part in OpenSSL version
                            if (!preg_match('/(\d+\.\d+\.\d+)/i', $fullVersion, $m)) {
                                $versions[$matches[1][$i]] = $fullVersion;
                            } else {
                                $versions[$matches[1][$i]] = $m[0];
                            }
                        }
                    }

                    // it doesn't appear that OpenSSL versions were reported upon until PHP 5.3+
                    switch (true) {
                        case !isset($versions['Header']):
                        case !isset($versions['Library']):
                        case $versions['Header'] == $versions['Library']:
                            define('CRYPT_RSA_MODE', self::MODE_OPENSSL);
                            break;
                        default:
                            define('CRYPT_RSA_MODE', self::MODE_INTERNAL);
                            define('MATH_BIGINTEGER_OPENSSL_DISABLE', true);
                    }
                    break;
                default:
                    define('CRYPT_RSA_MODE', self::MODE_INTERNAL);
            }
        }

        $this->zero = BigInteger::createFromDecimalString('0');
        $this->one = BigInteger::createFromDecimalString('1');

        $this->hash = new Hash('sha1');
        $this->hLen = 20;
        $this->hashName = 'sha1';
        $this->mgfHash = new Hash('sha1');
        $this->mgfHLen = 20;
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
        if ($type != self::PUBLIC_FORMAT_RAW && !is_string($key)) {
            return false;
        }

        switch ($type) {
            case self::PUBLIC_FORMAT_RAW:
                if (!is_array($key)) {
                    return false;
                }
                $components = [];
                switch (true) {
                    case isset($key['e']):
                        $components['publicExponent'] = $key['e']->copy();
                        break;
                    case isset($key['exponent']):
                        $components['publicExponent'] = $key['exponent']->copy();
                        break;
                    case isset($key['publicExponent']):
                        $components['publicExponent'] = $key['publicExponent']->copy();
                        break;
                    case isset($key[0]):
                        $components['publicExponent'] = $key[0]->copy();
                }
                switch (true) {
                    case isset($key['n']):
                        $components['modulus'] = $key['n']->copy();
                        break;
                    case isset($key['modulo']):
                        $components['modulus'] = $key['modulo']->copy();
                        break;
                    case isset($key['modulus']):
                        $components['modulus'] = $key['modulus']->copy();
                        break;
                    case isset($key[1]):
                        $components['modulus'] = $key[1]->copy();
                }

                return isset($components['modulus']) && isset($components['publicExponent']) ? $components : false;
            case self::PRIVATE_FORMAT_PKCS1:
            case self::PRIVATE_FORMAT_PKCS8:
            case self::PUBLIC_FORMAT_PKCS1:
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
                        case "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x03": // pbeWithMD5AndDES-CBC
                            if (ord($this->_string_shift($temp)) != self::ASN1_SEQUENCE) {
                                return false;
                            }
                            if ($this->_decodeLength($temp) != strlen($temp)) {
                                return false;
                            }
                            $this->_string_shift($temp); // assume it's an octet string
                            $salt = $this->_string_shift($temp, $this->_decodeLength($temp));
                            if (ord($this->_string_shift($temp)) != self::ASN1_INTEGER) {
                                return false;
                            }
                            $this->_decodeLength($temp);
                            list(, $iterationCount) = unpack('N', str_pad($temp, 4, chr(0), STR_PAD_LEFT));
                            $this->_string_shift($key); // assume it's an octet string
                            $length = $this->_decodeLength($key);
                            if (strlen($key) != $length) {
                                return false;
                            }

                            $crypto = new DES();
                            $crypto->setPassword($this->password, 'pbkdf1', 'md5', $salt, $iterationCount);
                            $key = $crypto->decrypt($key);
                            if ($key === false) {
                                return false;
                            }

                            return $this->_parseKey($key, self::PRIVATE_FORMAT_PKCS1);
                        default:
                            return false;
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

                if (!empty($key)) {
                    if (ord($this->_string_shift($key)) != self::ASN1_SEQUENCE) {
                        return false;
                    }
                    $this->_decodeLength($key);
                    while (!empty($key)) {
                        if (ord($this->_string_shift($key)) != self::ASN1_SEQUENCE) {
                            return false;
                        }
                        $this->_decodeLength($key);
                        $key = substr($key, 1);
                        $length = $this->_decodeLength($key);
                        $components['primes'][] = BigInteger::createFromBinaryString($this->_string_shift($key, $length));
                        $this->_string_shift($key);
                        $length = $this->_decodeLength($key);
                        $components['exponents'][] = BigInteger::createFromBinaryString($this->_string_shift($key, $length));
                        $this->_string_shift($key);
                        $length = $this->_decodeLength($key);
                        $components['coefficients'][] = BigInteger::createFromBinaryString($this->_string_shift($key, $length));
                    }
                }

                return $components;
            case self::PUBLIC_FORMAT_OPENSSH:
                $parts = explode(' ', $key, 3);

                $key = isset($parts[1]) ? base64_decode($parts[1]) : false;
                if ($key === false) {
                    return false;
                }

                $comment = isset($parts[2]) ? $parts[2] : false;

                $cleanup = substr($key, 0, 11) == "\0\0\0\7ssh-rsa";

                if (strlen($key) <= 4) {
                    return false;
                }
                extract(unpack('Nlength', $this->_string_shift($key, 4)));
                $publicExponent = BigInteger::createFromBinaryString($this->_string_shift($key, $length));
                if (strlen($key) <= 4) {
                    return false;
                }
                extract(unpack('Nlength', $this->_string_shift($key, 4)));
                $modulus = BigInteger::createFromBinaryString($this->_string_shift($key, $length));

                if ($cleanup && strlen($key)) {
                    if (strlen($key) <= 4) {
                        return false;
                    }
                    extract(unpack('Nlength', $this->_string_shift($key, 4)));
                    $realModulus = BigInteger::createFromBinaryString($this->_string_shift($key, $length));

                    return strlen($key) ? false : [
                        'modulus'        => $realModulus,
                        'publicExponent' => $modulus,
                        'comment'        => $comment,
                    ];
                } else {
                    return strlen($key) ? false : [
                        'modulus'        => $modulus,
                        'publicExponent' => $publicExponent,
                        'comment'        => $comment,
                    ];
                }
            case self::PRIVATE_FORMAT_XML:
            case self::PUBLIC_FORMAT_XML:
                $this->components = [];

                $xml = xml_parser_create('UTF-8');
                xml_set_object($xml, $this);
                xml_set_element_handler($xml, '_start_element_handler', '_stop_element_handler');
                xml_set_character_data_handler($xml, '_data_handler');
                // add <xml></xml> to account for "dangling" tags like <BitStrength>...</BitStrength> that are sometimes added
                if (!xml_parse($xml, '<xml>'.$key.'</xml>')) {
                    return false;
                }

                return isset($this->components['modulus']) && isset($this->components['publicExponent']) ? $this->components : false;
            // from PuTTY's SSHPUBK.C
            case self::PRIVATE_FORMAT_PUTTY:
                $components = [];
                $key = preg_split('#\r\n|\r|\n#', $key);
                $type = trim(preg_replace('#PuTTY-User-Key-File-2: (.+)#', '$1', $key[0]));
                if ($type != 'ssh-rsa') {
                    return false;
                }
                $encryption = trim(preg_replace('#Encryption: (.+)#', '$1', $key[1]));
                $comment = trim(preg_replace('#Comment: (.+)#', '$1', $key[2]));

                $publicLength = trim(preg_replace('#Public-Lines: (\d+)#', '$1', $key[3]));
                $public = base64_decode(implode('', array_map('trim', array_slice($key, 4, $publicLength))));
                $public = substr($public, 11);
                extract(unpack('Nlength', $this->_string_shift($public, 4)));
                $components['publicExponent'] = BigInteger::createFromBinaryString($this->_string_shift($public, $length));
                extract(unpack('Nlength', $this->_string_shift($public, 4)));
                $components['modulus'] = BigInteger::createFromBinaryString($this->_string_shift($public, $length));

                $privateLength = trim(preg_replace('#Private-Lines: (\d+)#', '$1', $key[$publicLength + 4]));
                $private = base64_decode(implode('', array_map('trim', array_slice($key, $publicLength + 5, $privateLength))));

                switch ($encryption) {
                    case 'aes256-cbc':
                        $symkey = '';
                        $sequence = 0;
                        while (strlen($symkey) < 32) {
                            $temp = pack('Na*', $sequence++, $this->password);
                            $symkey .= pack('H*', sha1($temp));
                        }
                        $symkey = substr($symkey, 0, 32);
                        $crypto = new AES();
                }

                if ($encryption != 'none') {
                    $crypto->setKey($symkey);
                    $crypto->disablePadding();
                    $private = $crypto->decrypt($private);
                    if ($private === false) {
                        return false;
                    }
                }

                extract(unpack('Nlength', $this->_string_shift($private, 4)));
                if (strlen($private) < $length) {
                    return false;
                }
                $components['privateExponent'] = BigInteger::createFromBinaryString($this->_string_shift($private, $length), true);
                extract(unpack('Nlength', $this->_string_shift($private, 4)));
                if (strlen($private) < $length) {
                    return false;
                }
                $components['primes'] = [1 => BigInteger::createFromBinaryString($this->_string_shift($private, $length), true)];
                extract(unpack('Nlength', $this->_string_shift($private, 4)));
                if (strlen($private) < $length) {
                    return false;
                }
                $components['primes'][] = BigInteger::createFromBinaryString($this->_string_shift($private, $length), true);

                $temp = $components['primes'][1]->subtract($this->one);
                $components['exponents'] = [1 => $components['publicExponent']->modInverse($temp)];
                $temp = $components['primes'][2]->subtract($this->one);
                $components['exponents'][] = $components['publicExponent']->modInverse($temp);

                extract(unpack('Nlength', $this->_string_shift($private, 4)));
                if (strlen($private) < $length) {
                    return false;
                }
                $components['coefficients'] = [2 => BigInteger::createFromBinaryString($this->_string_shift($private, $length), true)];

                return $components;
        }
    }

    /**
     * Start Element Handler.
     *
     * Called by xml_set_element_handler()
     *
     * @param resource $parser
     * @param string   $name
     * @param array    $attribs
     */
    private function _start_element_handler($parser, $name, $attribs)
    {
        //$name = strtoupper($name);
        switch ($name) {
            case 'MODULUS':
                $this->current = &$this->components['modulus'];
                break;
            case 'EXPONENT':
                $this->current = &$this->components['publicExponent'];
                break;
            case 'P':
                $this->current = &$this->components['primes'][1];
                break;
            case 'Q':
                $this->current = &$this->components['primes'][2];
                break;
            case 'DP':
                $this->current = &$this->components['exponents'][1];
                break;
            case 'DQ':
                $this->current = &$this->components['exponents'][2];
                break;
            case 'INVERSEQ':
                $this->current = &$this->components['coefficients'][2];
                break;
            case 'D':
                $this->current = &$this->components['privateExponent'];
        }
        $this->current = '';
    }

    /**
     * Stop Element Handler.
     */
    private function _stop_element_handler()
    {
        if (isset($this->current)) {
            $this->current = BigInteger::createFromBinaryString(base64_decode($this->current));
            unset($this->current);
        }
    }

    /**
     * Data Handler.
     *
     * Called by xml_set_character_data_handler()
     *
     * @param resource $parser
     * @param string   $data
     */
    public function _data_handler($parser, $data)
    {
        if (!isset($this->current) || is_object($this->current)) {
            return;
        }
        $this->current .= trim($data);
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
        if ($key instanceof self) {
            $this->privateKeyFormat = $key->privateKeyFormat;
            $this->publicKeyFormat = $key->publicKeyFormat;
            $this->k = $key->k;
            $this->hLen = $key->hLen;
            $this->sLen = $key->sLen;
            $this->mgfHLen = $key->mgfHLen;
            $this->encryptionMode = $key->encryptionMode;
            $this->signatureMode = $key->signatureMode;
            $this->password = $key->password;
            $this->configFile = $key->configFile;
            $this->comment = $key->comment;

            if (is_object($key->hash)) {
                $this->hash = new Hash($key->hash->getHash());
            }
            if (is_object($key->mgfHash)) {
                $this->mgfHash = new Hash($key->mgfHash->getHash());
            }

            if (is_object($key->modulus)) {
                $this->modulus = $key->modulus->copy();
            }
            if (is_object($key->exponent)) {
                $this->exponent = $key->exponent->copy();
            }
            if (is_object($key->publicExponent)) {
                $this->publicExponent = $key->publicExponent->copy();
            }

            $this->primes = [];
            $this->exponents = [];
            $this->coefficients = [];

            foreach ($this->primes as $prime) {
                $this->primes[] = $prime->copy();
            }
            foreach ($this->exponents as $exponent) {
                $this->exponents[] = $exponent->copy();
            }
            foreach ($this->coefficients as $coefficient) {
                $this->coefficients[] = $coefficient->copy();
            }

            return true;
        }

        if ($type === false) {
            $types = [
                self::PUBLIC_FORMAT_RAW,
                self::PRIVATE_FORMAT_PKCS1,
                self::PRIVATE_FORMAT_XML,
                self::PRIVATE_FORMAT_PUTTY,
                self::PUBLIC_FORMAT_OPENSSH,
            ];
            foreach ($types as $type) {
                $components = $this->_parseKey($key, $type);
                if ($components !== false) {
                    break;
                }
            }
        } else {
            $components = $this->_parseKey($key, $type);
        }

        if ($components === false) {
            return false;
        }

        if (isset($components['comment']) && $components['comment'] !== false) {
            $this->comment = $components['comment'];
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

        switch ($type) {
            case self::PUBLIC_FORMAT_OPENSSH:
            case self::PUBLIC_FORMAT_RAW:
                $this->setPublicKey();
                break;
            case self::PRIVATE_FORMAT_PKCS1:
                switch (true) {
                    case strpos($key, '-BEGIN PUBLIC KEY-') !== false:
                    case strpos($key, '-BEGIN RSA PUBLIC KEY-') !== false:
                        $this->setPublicKey();
                }
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
        switch ($hash) {
            case 'sha1':
                $this->hLen = 20;
                break;
            case 'sha256':
                $this->hLen = 32;
                break;
            case 'sha384':
                $this->hLen = 48;
                break;
            case 'sha512':
                $this->hLen = 64;
                break;
            default:
                throw new \InvalidArgumentException('Unsupported hash algorithm.');
        }
        $this->hash = new Hash($hash);
    }

    /**
     * Determines which hashing function should be used for the mask generation function.
     *
     * @param string $hash
     */
    public function setMGFHash($hash)
    {
        switch ($hash) {
            case 'sha1':
                $this->mgfHLen = 20;
                break;
            case 'sha256':
                $this->mgfHash = 32;
                break;
            case 'sha384':
                $this->mgfHash = 48;
                break;
            case 'sha512':
                $this->mgfHash = 64;
                break;
            default:
                throw new \InvalidArgumentException('Unsupported hash algorithm.');
        }
        $this->mgfHash = new Hash($hash);
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
            user_error('Integer too large');

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

        if (defined('CRYPT_RSA_DISABLE_BLINDING')) {
            $m_i = [
                1 => $x->modPow($this->exponents[1], $this->primes[1]),
                2 => $x->modPow($this->exponents[2], $this->primes[2]),
            ];
            $h = $m_i[1]->subtract($m_i[2]);
            $h = $h->multiply($this->coefficients[2]);
            list(, $h) = $h->divide($this->primes[1]);
            $m = $m_i[2]->add($h->multiply($this->primes[2]));

            $r = $this->primes[1];
            for ($i = 3; $i <= $num_primes; $i++) {
                $m_i = $x->modPow($this->exponents[$i], $this->primes[$i]);

                $r = $r->multiply($this->primes[$i - 1]);

                $h = $m_i->subtract($m);
                $h = $h->multiply($this->coefficients[$i]);
                list(, $h) = $h->divide($this->primes[$i]);

                $m = $m->add($r->multiply($h));
            }
        } else {
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
            user_error('Message representative out of range');

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
            user_error('Ciphertext representative out of range');

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
            user_error('Message representative out of range');

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
            user_error('Signature representative out of range');

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
        $count = ceil($maskLen / $this->mgfHLen);
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

        if ($mLen > $this->k - 2 * $this->hLen - 2) {
            user_error('Message too long');

            return false;
        }

        // EME-OAEP encoding

        $lHash = $this->hash->hash($l);
        $ps = str_repeat(chr(0), $this->k - $mLen - 2 * $this->hLen - 2);
        $db = $lHash.$ps.chr(1).$m;
        $seed = random_bytes($this->hLen);
        $dbMask = $this->_mgf1($seed, $this->k - $this->hLen - 1);
        $maskedDB = $db ^ $dbMask;
        $seedMask = $this->_mgf1($maskedDB, $this->hLen);
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

        if (strlen($c) != $this->k || $this->k < 2 * $this->hLen + 2) {
            user_error('Decryption error');

            return false;
        }

        // RSA decryption

        $c = $this->_os2ip($c);
        $m = $this->_rsadp($c);
        if ($m === false) {
            user_error('Decryption error');

            return false;
        }
        $em = $this->_i2osp($m, $this->k);

        // EME-OAEP decoding

        $lHash = $this->hash->hash($l);
        $y = ord($em[0]);
        $maskedSeed = substr($em, 1, $this->hLen);
        $maskedDB = substr($em, $this->hLen + 1);
        $seedMask = $this->_mgf1($maskedDB, $this->hLen);
        $seed = $maskedSeed ^ $seedMask;
        $dbMask = $this->_mgf1($seed, $this->k - $this->hLen - 1);
        $db = $maskedDB ^ $dbMask;
        $lHash2 = substr($db, 0, $this->hLen);
        $m = substr($db, $this->hLen);
        if ($lHash != $lHash2) {
            user_error('Decryption error');

            return false;
        }
        $m = ltrim($m, chr(0));
        if (ord($m[0]) != 1) {
            user_error('Decryption error');

            return false;
        }

        // Output the message M

        return substr($m, 1);
    }

    /**
     * RSAES-PKCS1-V1_5-ENCRYPT.
     *
     * @param string $m
     *
     * @return string
     */
    private function _rsaes_pkcs1_v1_5_encrypt($m)
    {
        $mLen = strlen($m);

        // Length checking

        if ($mLen > $this->k - 11) {
            user_error('Message too long');

            return false;
        }

        // EME-PKCS1-v1_5 encoding

        $psLen = $this->k - $mLen - 3;
        $ps = '';
        while (strlen($ps) != $psLen) {
            $temp = random_bytes($psLen - strlen($ps));
            $temp = str_replace("\x00", '', $temp);
            $ps .= $temp;
        }
        $type = 2;
        // see the comments of _rsaes_pkcs1_v1_5_decrypt() to understand why this is being done
        if (defined('CRYPT_RSA_PKCS15_COMPAT') && (!isset($this->publicExponent) || $this->exponent !== $this->publicExponent)) {
            $type = 1;
            // "The padding string PS shall consist of k-3-||D|| octets. ... for block type 01, they shall have value FF"
            $ps = str_repeat("\xFF", $psLen);
        }
        $em = chr(0).chr($type).$ps.chr(0).$m;

        // RSA encryption
        $m = $this->_os2ip($em);
        $c = $this->_rsaep($m);
        $c = $this->_i2osp($c, $this->k);

        // Output the ciphertext C

        return $c;
    }

    /**
     * RSAES-PKCS1-V1_5-DECRYPT.
     *
     * @param string $c
     *
     * @return string
     */
    private function _rsaes_pkcs1_v1_5_decrypt($c)
    {
        // Length checking

        if (strlen($c) != $this->k) { // or if k < 11
            user_error('Decryption error');

            return false;
        }

        // RSA decryption

        $c = $this->_os2ip($c);
        $m = $this->_rsadp($c);

        if ($m === false) {
            user_error('Decryption error');

            return false;
        }
        $em = $this->_i2osp($m, $this->k);

        // EME-PKCS1-v1_5 decoding

        if (ord($em[0]) != 0 || ord($em[1]) > 2) {
            user_error('Decryption error');

            return false;
        }

        $ps = substr($em, 2, strpos($em, chr(0), 2) - 2);
        $m = substr($em, strlen($ps) + 3);

        if (strlen($ps) < 8) {
            user_error('Decryption error');

            return false;
        }

        // Output M

        return $m;
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
        $sLen = $this->sLen ? $this->sLen : $this->hLen;

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hLen + $sLen + 2) {
            user_error('Encoding error');

            return false;
        }

        $salt = random_bytes($sLen);
        $m2 = "\0\0\0\0\0\0\0\0".$mHash.$salt;
        $h = $this->hash->hash($m2);
        $ps = str_repeat(chr(0), $emLen - $sLen - $this->hLen - 2);
        $db = $ps.chr(1).$salt;
        $dbMask = $this->_mgf1($h, $emLen - $this->hLen - 1);
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
        $sLen = $this->sLen ? $this->sLen : $this->hLen;

        $mHash = $this->hash->hash($m);
        if ($emLen < $this->hLen + $sLen + 2) {
            return false;
        }

        if ($em[strlen($em) - 1] != chr(0xBC)) {
            return false;
        }

        $maskedDB = substr($em, 0, -$this->hLen - 1);
        $h = substr($em, -$this->hLen - 1, $this->hLen);
        $temp = chr(0xFF << ($emBits & 7));
        if ((~$maskedDB[0] & $temp) != $temp) {
            return false;
        }
        $dbMask = $this->_mgf1($h, $emLen - $this->hLen - 1);
        $db = $maskedDB ^ $dbMask;
        $db[0] = ~chr(0xFF << ($emBits & 7)) & $db[0];
        $temp = $emLen - $this->hLen - $sLen - 2;
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
            user_error('Invalid signature');

            return false;
        }

        // RSA verification

        $modBits = 8 * $this->k;

        $s2 = $this->_os2ip($s);
        $m2 = $this->_rsavp1($s2);
        if ($m2 === false) {
            user_error('Invalid signature');

            return false;
        }
        $em = $this->_i2osp($m2, $modBits >> 3);
        if ($em === false) {
            user_error('Invalid signature');

            return false;
        }

        // EMSA-PSS verification

        return $this->_emsa_pss_verify($m, $em, $modBits - 1);
    }

    /**
     * EMSA-PKCS1-V1_5-ENCODE.
     *
     * @param string $m
     * @param int    $emLen
     *
     * @return string
     */
    private function _emsa_pkcs1_v1_5_encode($m, $emLen)
    {
        $h = $this->hash->hash($m);
        if ($h === false) {
            return false;
        }

        // see http://tools.ietf.org/html/rfc3447#page-43
        switch ($this->hashName) {
            case 'md2':
                $t = pack('H*', '3020300c06082a864886f70d020205000410');
                break;
            case 'md5':
                $t = pack('H*', '3020300c06082a864886f70d020505000410');
                break;
            case 'sha1':
                $t = pack('H*', '3021300906052b0e03021a05000414');
                break;
            case 'sha256':
                $t = pack('H*', '3031300d060960864801650304020105000420');
                break;
            case 'sha384':
                $t = pack('H*', '3041300d060960864801650304020205000430');
                break;
            case 'sha512':
                $t = pack('H*', '3051300d060960864801650304020305000440');
        }
        $t .= $h;
        $tLen = strlen($t);

        if ($emLen < $tLen + 11) {
            user_error('Intended encoded message length too short');

            return false;
        }

        $ps = str_repeat(chr(0xFF), $emLen - $tLen - 3);

        $em = "\0\1$ps\0$t";

        return $em;
    }

    /**
     * RSASSA-PKCS1-V1_5-SIGN.
     *
     * @param string $m
     *
     * @return string
     */
    private function _rsassa_pkcs1_v1_5_sign($m)
    {
        // EMSA-PKCS1-v1_5 encoding

        $em = $this->_emsa_pkcs1_v1_5_encode($m, $this->k);
        if ($em === false) {
            user_error('RSA modulus too short');

            return false;
        }

        // RSA signature

        $m = $this->_os2ip($em);
        $s = $this->_rsasp1($m);
        $s = $this->_i2osp($s, $this->k);

        // Output the signature S

        return $s;
    }

    /**
     * RSASSA-PKCS1-V1_5-VERIFY.
     *
     * @param string $m
     *
     * @return string
     */
    private function _rsassa_pkcs1_v1_5_verify($m, $s)
    {
        // Length checking

        if (strlen($s) != $this->k) {
            user_error('Invalid signature');

            return false;
        }

        // RSA verification

        $s = $this->_os2ip($s);
        $m2 = $this->_rsavp1($s);
        if ($m2 === false) {
            user_error('Invalid signature');

            return false;
        }
        $em = $this->_i2osp($m2, $this->k);
        if ($em === false) {
            user_error('Invalid signature');

            return false;
        }

        // EMSA-PKCS1-v1_5 encoding

        $em2 = $this->_emsa_pkcs1_v1_5_encode($m, $this->k);
        if ($em2 === false) {
            user_error('RSA modulus too short');

            return false;
        }

        // Compare
        return $this->_equals($em, $em2);
    }

    /**
     * Set Encryption Mode.
     *
     * Valid values include self::ENCRYPTION_OAEP and self::ENCRYPTION_PKCS1.
     *
     * @param int $mode
     */
    public function setEncryptionMode($mode)
    {
        $this->encryptionMode = $mode;
    }

    /**
     * Set Signature Mode.
     *
     * Valid values include self::SIGNATURE_PSS and self::SIGNATURE_PKCS1
     *
     * @param int $mode
     */
    public function setSignatureMode($mode)
    {
        $this->signatureMode = $mode;
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
        switch ($this->encryptionMode) {
            case self::ENCRYPTION_PKCS1:
                $length = $this->k - 11;
                if ($length <= 0) {
                    return false;
                }

                $plaintext = str_split($plaintext, $length);
                $ciphertext = '';
                foreach ($plaintext as $m) {
                    $ciphertext .= $this->_rsaes_pkcs1_v1_5_encrypt($m);
                }

                return $ciphertext;
            case self::ENCRYPTION_OAEP:
            default:
                $length = $this->k - 2 * $this->hLen - 2;
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

        switch ($this->encryptionMode) {
            case self::ENCRYPTION_PKCS1:
                $decrypt = '_rsaes_pkcs1_v1_5_decrypt';
                break;
            case self::ENCRYPTION_OAEP:
            default:
                $decrypt = '_rsaes_oaep_decrypt';
        }

        foreach ($ciphertext as $c) {
            $temp = $this->$decrypt($c);
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

        switch ($this->signatureMode) {
            case self::SIGNATURE_PKCS1:
                return $this->_rsassa_pkcs1_v1_5_sign($message);
            case self::SIGNATURE_PSS:
            default:
                return $this->_rsassa_pss_sign($message);
        }
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

        switch ($this->signatureMode) {
            case self::SIGNATURE_PKCS1:
                return $this->_rsassa_pkcs1_v1_5_verify($message, $signature);
            case self::SIGNATURE_PSS:
            default:
                return $this->_rsassa_pss_verify($message, $signature);
        }
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
     * @param string $key  optional
     * @param int    $type optional
     *
     * @return bool
     */
    private function setPublicKey($key = false, $type = false)
    {
        // if a public key has already been loaded return false
        if (!empty($this->publicExponent)) {
            return false;
        }

        if ($key === false && !empty($this->modulus)) {
            $this->publicExponent = $this->exponent;

            return true;
        }

        if ($type === false) {
            $types = [
                self::PUBLIC_FORMAT_RAW,
                self::PUBLIC_FORMAT_PKCS1,
                self::PUBLIC_FORMAT_XML,
                self::PUBLIC_FORMAT_OPENSSH,
            ];
            foreach ($types as $type) {
                $components = $this->_parseKey($key, $type);
                if ($components !== false) {
                    break;
                }
            }
        } else {
            $components = $this->_parseKey($key, $type);
        }

        if ($components === false) {
            return false;
        }

        if (empty($this->modulus) || !$this->modulus->equals($components['modulus'])) {
            $this->modulus = $components['modulus'];
            $this->exponent = $this->publicExponent = $components['publicExponent'];

            return true;
        }

        $this->publicExponent = $components['publicExponent'];

        return true;
    }
}
