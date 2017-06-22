<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Assert\Assertion;
use Jose\Component\Encryption\Decrypter;
use Jose\Factory\AlgorithmManagerFactory;
use Jose\Factory\CompressionManagerFactory;
use Jose\Object\JWE;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSet;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWS;
use Jose\Object\JWTInterface;

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
final class Loader
{
    /**
     * @param string                    $input
     * @param JWKInterface $jwk
     * @param string[]                  $allowed_key_encryption_algorithms
     * @param string[]                  $allowed_content_encryption_algorithms
     * @param null|int                  $recipient_index
     *
     * @return JWS|JWE If the data has been loaded.
     */
    public static function loadAndDecryptUsingKey(string $input, JWKInterface $jwk, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, ?int &$recipient_index = null): JWTInterface
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        return self::loadAndDecrypt($input, $jwk_set, $allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, $recipient_index);
    }

    /**
     * @param string                       $input
     * @param JWKSetInterface $jwk_set
     * @param string[]                     $allowed_key_encryption_algorithms
     * @param string[]                     $allowed_content_encryption_algorithms
     * @param null|int                     $recipient_index
     *
     * @return JWE If the data has been loaded.
     */
    public static function loadAndDecryptUsingKeySet(string $input, JWKSetInterface $jwk_set, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, ?int &$recipient_index = null): JWE
    {
        return self::loadAndDecrypt($input, $jwk_set, $allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, $recipient_index);
    }

    /**
     * @param string                    $input
     * @param JWKInterface $jwk
     * @param string[]                  $allowed_algorithms
     * @param null|int                  $signature_index
     *
     * @return JWS If the data has been loaded.
     */
    public static function loadAndVerifySignatureUsingKey($input, JWKInterface $jwk, array $allowed_algorithms, ?int &$signature_index = null): JWS
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        return self::loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $signature_index);
    }

    /**
     * @param string                       $input
     * @param JWKSetInterface $jwk_set
     * @param string[]                     $allowed_algorithms
     * @param null|int                     $signature_index
     *
     * @return JWS If the data has been loaded.
     */
    public static function loadAndVerifySignatureUsingKeySet(string $input, JWKSetInterface $jwk_set, array $allowed_algorithms, ?int &$signature_index = null): JWS
    {
        return self::loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $signature_index);
    }

    /**
     * @param string                    $input
     * @param JWKInterface $jwk
     * @param string[]                  $allowed_algorithms
     * @param string                    $detached_payload
     * @param null|int                  $signature_index
     *
     * @return JWS If the data has been loaded.
     */
    public static function loadAndVerifySignatureUsingKeyAndDetachedPayload(string $input, JWKInterface $jwk, array $allowed_algorithms, $detached_payload, ?int &$signature_index = null): JWS
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        return self::loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $signature_index);
    }

    /**
     * @param string                       $input
     * @param JWKSetInterface $jwk_set
     * @param string[]                     $allowed_algorithms
     * @param string                       $detached_payload
     * @param null|int                     $signature_index
     *
     * @return JWS If the data has been loaded.
     */
    public static function loadAndVerifySignatureUsingKeySetAndDetachedPayload(string $input, JWKSetInterface $jwk_set, array $allowed_algorithms, string $detached_payload, ?int &$signature_index = null): JWS
    {
        return self::loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $signature_index);
    }

    /**
     * @param string                       $input
     * @param JWKSetInterface $jwk_set
     * @param array                        $allowed_key_encryption_algorithms
     * @param array                        $allowed_content_encryption_algorithms
     * @param null|int                     $recipient_index
     *
     * @return JWE
     */
    private static function loadAndDecrypt(string $input, JWKSetInterface $jwk_set, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, ?int &$recipient_index = null): JWE
    {
        $jwt = self::load($input);
        Assertion::isInstanceOf($jwt, JWE::class, 'The input is not a valid JWE');

        $keyEncryptionAlgorithmManager = AlgorithmManagerFactory::createFromAlgorithmName($allowed_key_encryption_algorithms);
        $contentEncryptionAlgorithmManager = AlgorithmManagerFactory::createFromAlgorithmName($allowed_content_encryption_algorithms);
        $compressionManager = CompressionManagerFactory::createCompressionManager(['DEF', 'ZLIB', 'GZ']);
        $decrypter = new Decrypter($keyEncryptionAlgorithmManager, $contentEncryptionAlgorithmManager,$compressionManager);
        $decrypter->decryptUsingKeySet($jwt, $jwk_set, $recipient_index);

        return $jwt;
    }

    /**
     * @param string                       $input
     * @param JWKSetInterface $jwk_set
     * @param array                        $allowed_algorithms
     * @param string|null                  $detached_payload
     * @param null|int                     $signature_index
     *
     * @return JWS
     */
    private static function loadAndVerifySignature(string $input, JWKSetInterface $jwk_set, array $allowed_algorithms, ?string $detached_payload = null, ?int &$signature_index = null): JWS
    {
        $jwt = self::load($input);
        Assertion::isInstanceOf($jwt, JWS::class, 'The input is not a valid JWS.');
        $signatureAlgorithmManager = AlgorithmManagerFactory::createFromAlgorithmName($allowed_algorithms);
        $verifier = new Verifier($signatureAlgorithmManager);

        $verifier->verifyWithKeySet($jwt, $jwk_set, $detached_payload, $signature_index);

        return $jwt;
    }

    /**
     * Load data and try to return a JWS object, a JWE object or a list of these objects.
     * If the result is a JWE (list), nothing is decrypted and method `decrypt` must be executed
     * If the result is a JWS (list), no signature is verified and method `verifySignature` must be executed.
     *
     * @param string $input A string that represents a JSON Web Token message
     *
     * @return JWS|JWE If the data has been loaded.
     */
    public static function load(string $input): JWTInterface
    {
        $json = self::convert($input);
        if (array_key_exists('signatures', $json)) {
            return Util\JWSLoader::loadSerializedJsonJWS($json);
        }
        if (array_key_exists('recipients', $json)) {
            return Util\JWELoader::loadSerializedJsonJWE($json);
        }
    }

    /**
     * @param string $input
     *
     * @return array
     */
    private static function convert(string $input): array
    {
        if (is_array($data = json_decode($input, true))) {
            if (array_key_exists('signatures', $data) || array_key_exists('recipients', $data)) {
                return $data;
            } elseif (array_key_exists('signature', $data)) {
                return self::fromFlattenedSerializationSignatureToSerialization($data);
            } elseif (array_key_exists('ciphertext', $data)) {
                return self::fromFlattenedSerializationRecipientToSerialization($data);
            }
        } elseif (is_string($input)) {
            return self::fromCompactSerializationToSerialization($input);
        }
        throw new \InvalidArgumentException('Unsupported input');
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function fromFlattenedSerializationRecipientToSerialization(array $input): array
    {
        $recipient = [];
        foreach (['header', 'encrypted_key'] as $key) {
            if (array_key_exists($key, $input)) {
                $recipient[$key] = $input[$key];
            }
        }
        $recipients = [
            'ciphertext' => $input['ciphertext'],
            'recipients' => [$recipient],
        ];
        foreach (['protected', 'unprotected', 'iv', 'aad', 'tag'] as $key) {
            if (array_key_exists($key, $input)) {
                $recipients[$key] = $input[$key];
            }
        }

        return $recipients;
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private static function fromFlattenedSerializationSignatureToSerialization(array $input): array
    {
        $signature = [
            'signature' => $input['signature'],
        ];
        foreach (['protected', 'header'] as $key) {
            if (array_key_exists($key, $input)) {
                $signature[$key] = $input[$key];
            }
        }

        $temp = [];
        if (!empty($input['payload'])) {
            $temp['payload'] = $input['payload'];
        }
        $temp['signatures'] = [$signature];

        return $temp;
    }

    /**
     * @param string $input
     *
     * @return array
     */
    private static function fromCompactSerializationToSerialization(string $input): array
    {
        $parts = explode('.', $input);
        switch (count($parts)) {
            case 3:
                return self::fromCompactSerializationSignatureToSerialization($parts);
            case 5:
                return self::fromCompactSerializationRecipientToSerialization($parts);
            default:
                throw new \InvalidArgumentException('Unsupported input');
        }
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private static function fromCompactSerializationRecipientToSerialization(array $parts): array
    {
        $recipient = [];
        if (!empty($parts[1])) {
            $recipient['encrypted_key'] = $parts[1];
        }

        $recipients = [
            'recipients' => [$recipient],
        ];
        foreach ([0 => 'protected', 2 => 'iv', 3 => 'ciphertext', 4 => 'tag'] as $part => $key) {
            if (!empty($parts[$part])) {
                $recipients[$key] = $parts[$part];
            }
        }

        return $recipients;
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private static function fromCompactSerializationSignatureToSerialization(array $parts): array
    {
        $temp = [];

        if (!empty($parts[1])) {
            $temp['payload'] = $parts[1];
        }
        $temp['signatures'] = [[
            'protected' => $parts[0],
            'signature' => $parts[2],
        ]];

        return $temp;
    }
}
