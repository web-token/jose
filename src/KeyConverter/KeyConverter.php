<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\KeyConverter;

use Assert\Assertion;
use Base64Url\Base64Url;

/**
 * This class will help you to load an EC key or a RSA key/certificate (private or public) and get values to create a JWK object.
 */
final class KeyConverter
{
    /**
     * @param string $file
     *
     * @throws \InvalidArgumentException
     *
     * @return array
     */
    public static function loadKeyFromCertificateFile($file)
    {
        Assertion::true(file_exists($file), sprintf('File "%s" does not exist.', $file));
        $content = file_get_contents($file);

        return self::loadKeyFromCertificate($content);
    }

    /**
     * @param string $certificate
     *
     * @throws \InvalidArgumentException
     *
     * @return array
     */
    public static function loadKeyFromCertificate($certificate)
    {
        try {
            $res = openssl_x509_read($certificate);
        } catch (\Exception $e) {
            $certificate = self::convertDerToPem($certificate);
            $res = openssl_x509_read($certificate);
        }
        Assertion::false(false === $res, 'Unable to load the certificate');

        $values = self::loadKeyFromX509Resource($res);
        openssl_x509_free($res);

        return $values;
    }

    /**
     * @param resource $res
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadKeyFromX509Resource($res)
    {
        $key = openssl_get_publickey($res);

        $details = openssl_pkey_get_details($key);
        if (isset($details['key'])) {
            $values = self::loadKeyFromPEM($details['key']);
            openssl_x509_export($res, $out);
            $values['x5c'] = [trim(preg_replace('#-.*-#', '', $out))];

            if (function_exists('openssl_x509_fingerprint')) {
                $values['x5t'] = Base64Url::encode(openssl_x509_fingerprint($res, 'sha1', true));
                $values['x5t#256'] = Base64Url::encode(openssl_x509_fingerprint($res, 'sha256', true));
            } else {
                openssl_x509_export($res, $pem);
                $values['x5t'] = Base64Url::encode(self::calculateX509Fingerprint($pem, 'sha1', true));
                $values['x5t#256'] = Base64Url::encode(self::calculateX509Fingerprint($pem, 'sha256', true));
            }

            return $values;
        }
        throw new \InvalidArgumentException('Unable to load the certificate');
    }

    /**
     * @param string      $file
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadFromKeyFile($file, $password = null)
    {
        $content = file_get_contents($file);

        return self::loadFromKey($content, $password);
    }

    /**
     * @param string      $key
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    public static function loadFromKey($key, $password = null)
    {
        try {
            return self::loadKeyFromDER($key, $password);
        } catch (\Exception $e) {
            return self::loadKeyFromPEM($key, $password);
        }
    }

    /**
     * @param string      $der
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    private static function loadKeyFromDER($der, $password = null)
    {
        $pem = self::convertDerToPem($der);

        return self::loadKeyFromPEM($pem, $password);
    }

    /**
     * @param string      $pem
     * @param null|string $password
     *
     * @throws \Exception
     *
     * @return array
     */
    private static function loadKeyFromPEM($pem, $password = null)
    {
        if (preg_match('#DEK-Info: (.+),(.+)#', $pem, $matches)) {
            $pem = self::decodePem($pem, $matches, $password);
        }

        self::sanitizePEM($pem);

        $res = openssl_pkey_get_private($pem);
        if ($res === false) {
            $res = openssl_pkey_get_public($pem);
        }
        Assertion::false($res === false, 'Unable to load the key');

        $details = openssl_pkey_get_details($res);
        Assertion::isArray($details, 'Unable to get details of the key');
        Assertion::keyExists($details, 'type', 'Unable to get details of the key');

        switch ($details['type']) {
            case OPENSSL_KEYTYPE_EC:
                $ec_key = new ECKey($pem);

                return $ec_key->toArray();
            case OPENSSL_KEYTYPE_RSA:
                 $rsa_key = new RSAKey($pem);

                 return $rsa_key->toArray();
            default:
                throw new \InvalidArgumentException('Unsupported key type');
        }
    }

    /**
     * This method modify the PEM to get 64 char lines and fix bug with old OpenSSL versions.
     *
     * @param string $pem
     */
    private static function sanitizePEM(&$pem)
    {
        preg_match_all('#(-.*-)#', $pem, $matches, PREG_PATTERN_ORDER);
        $ciphertext = preg_replace('#-.*-|\r|\n| #', '', $pem);

        $pem = $matches[0][0].PHP_EOL;
        $pem .= chunk_split($ciphertext, 64, PHP_EOL);
        $pem .= $matches[0][1].PHP_EOL;
    }

    /**
     * @param array $x5c
     *
     * @return array
     */
    public static function loadFromX5C(array $x5c)
    {
        $certificate = null;
        $last_issuer = null;
        $last_subject = null;
        foreach ($x5c as $cert) {
            $current_cert = '-----BEGIN CERTIFICATE-----'.PHP_EOL.$cert.PHP_EOL.'-----END CERTIFICATE-----';
            $x509 = openssl_x509_read($current_cert);
            if (false === $x509) {
                $last_issuer = null;
                $last_subject = null;
                break;
            }
            $parsed = openssl_x509_parse($x509);

            openssl_x509_free($x509);
            if (false === $parsed) {
                $last_issuer = null;
                $last_subject = null;
                break;
            }
            if (null === $last_subject) {
                $last_subject = $parsed['subject'];
                $last_issuer = $parsed['issuer'];
                $certificate = $current_cert;
            } else {
                if (json_encode($last_issuer) === json_encode($parsed['subject'])) {
                    $last_subject = $parsed['subject'];
                    $last_issuer = $parsed['issuer'];
                } else {
                    $last_issuer = null;
                    $last_subject = null;
                    break;
                }
            }
        }
        Assertion::false(
            null === $last_issuer || json_encode($last_issuer) !== json_encode($last_subject),
            'Invalid certificate chain.'
        );

        return self::loadKeyFromCertificate($certificate);
    }

    /**
     * @param string      $pem
     * @param string[]    $matches
     * @param null|string $password
     *
     * @return string
     */
    private static function decodePem($pem, array $matches, $password = null)
    {
        Assertion::notNull($password, 'Password required for encrypted keys.');

        $iv = pack('H*', trim($matches[2]));
        $iv_sub = mb_substr($iv, 0, 8, '8bit');
        $symkey = pack('H*', md5($password.$iv_sub));
        $symkey .= pack('H*', md5($symkey.$password.$iv_sub));
        $key = preg_replace('#^(?:Proc-Type|DEK-Info): .*#m', '', $pem);
        $ciphertext = base64_decode(preg_replace('#-.*-|\r|\n#', '', $key));

        $decoded = openssl_decrypt($ciphertext, strtolower($matches[1]), $symkey, true, $iv);

        $number = preg_match_all('#-{5}.*-{5}#', $pem, $result);
        Assertion::eq($number, 2, 'Unable to load the key');

        $pem = $result[0][0].PHP_EOL;
        $pem .= chunk_split(base64_encode($decoded), 64);
        $pem .= $result[0][1].PHP_EOL;

        return $pem;
    }

    /**
     * @param string $der_data
     *
     * @return string
     */
    private static function convertDerToPem($der_data)
    {
        $pem = chunk_split(base64_encode($der_data), 64, PHP_EOL);
        $pem = '-----BEGIN CERTIFICATE-----'.PHP_EOL.$pem.'-----END CERTIFICATE-----'.PHP_EOL;

        return $pem;
    }

    /**
     * @param string $pem
     * @param string $algorithm
     * @param bool   $binary
     *
     * @return string
     */
    private static function calculateX509Fingerprint($pem, $algorithm, $binary = false)
    {
        $pem = preg_replace('#-.*-|\r|\n#', '', $pem);
        $bin = base64_decode($pem);

        return hash($algorithm, $bin, $binary);
    }
}
