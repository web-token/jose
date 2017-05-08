<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Assert\Assertion;
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
    public function loadAndDecryptUsingKey(string $input, JWKInterface $jwk, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, ?int &$recipient_index = null): JWTInterface
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        return $this->loadAndDecrypt($input, $jwk_set, $allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, $recipient_index);
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
    public function loadAndDecryptUsingKeySet(string $input, JWKSetInterface $jwk_set, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, ?int &$recipient_index = null): JWE
    {
        return $this->loadAndDecrypt($input, $jwk_set, $allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, $recipient_index);
    }

    /**
     * @param string                    $input
     * @param JWKInterface $jwk
     * @param string[]                  $allowed_algorithms
     * @param null|int                  $signature_index
     *
     * @return JWS If the data has been loaded.
     */
    public function loadAndVerifySignatureUsingKey($input, JWKInterface $jwk, array $allowed_algorithms, ?int &$signature_index = null): JWS
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $signature_index);
    }

    /**
     * @param string                       $input
     * @param JWKSetInterface $jwk_set
     * @param string[]                     $allowed_algorithms
     * @param null|int                     $signature_index
     *
     * @return JWS If the data has been loaded.
     */
    public function loadAndVerifySignatureUsingKeySet(string $input, JWKSetInterface $jwk_set, array $allowed_algorithms, ?int &$signature_index = null): JWS
    {
        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $signature_index);
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
    public function loadAndVerifySignatureUsingKeyAndDetachedPayload(string $input, JWKInterface $jwk, array $allowed_algorithms, $detached_payload, ?int &$signature_index = null): JWS
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $signature_index);
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
    public function loadAndVerifySignatureUsingKeySetAndDetachedPayload(string $input, JWKSetInterface $jwk_set, array $allowed_algorithms, string $detached_payload, ?int &$signature_index = null): JWS
    {
        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $signature_index);
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
    private function loadAndDecrypt(string $input, JWKSetInterface $jwk_set, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, ?int &$recipient_index = null): JWE
    {
        $jwt = $this->load($input);
        Assertion::isInstanceOf($jwt, JWE::class, 'The input is not a valid JWE');
        $decrypted = Decrypter::createDecrypter($allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, ['DEF', 'ZLIB', 'GZ']);

        $decrypted->decryptUsingKeySet($jwt, $jwk_set, $recipient_index);

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
    private function loadAndVerifySignature(string $input, JWKSetInterface $jwk_set, array $allowed_algorithms, ?string $detached_payload = null, ?int &$signature_index = null): JWS
    {
        $jwt = $this->load($input);
        Assertion::isInstanceOf($jwt, JWS::class, 'The input is not a valid JWS.');
        $verifier = Verifier::createVerifier($allowed_algorithms);

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
    public function load(string $input): JWTInterface
    {
        $json = $this->convert($input);
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
    private function convert(string $input): array
    {
        if (is_array($data = json_decode($input, true))) {
            if (array_key_exists('signatures', $data) || array_key_exists('recipients', $data)) {
                return $data;
            } elseif (array_key_exists('signature', $data)) {
                return $this->fromFlattenedSerializationSignatureToSerialization($data);
            } elseif (array_key_exists('ciphertext', $data)) {
                return $this->fromFlattenedSerializationRecipientToSerialization($data);
            }
        } elseif (is_string($input)) {
            return $this->fromCompactSerializationToSerialization($input);
        }
        throw new \InvalidArgumentException('Unsupported input');
    }

    /**
     * @param array $input
     *
     * @return array
     */
    private function fromFlattenedSerializationRecipientToSerialization(array $input): array
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
    private function fromFlattenedSerializationSignatureToSerialization(array $input): array
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
    private function fromCompactSerializationToSerialization(string $input): array
    {
        $parts = explode('.', $input);
        switch (count($parts)) {
            case 3:
                return $this->fromCompactSerializationSignatureToSerialization($parts);
            case 5:
                return $this->fromCompactSerializationRecipientToSerialization($parts);
            default:
                throw new \InvalidArgumentException('Unsupported input');
        }
    }

    /**
     * @param array $parts
     *
     * @return array
     */
    private function fromCompactSerializationRecipientToSerialization(array $parts): array
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
    private function fromCompactSerializationSignatureToSerialization(array $parts): array
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
