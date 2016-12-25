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

/**
 * Class able to load JWS or JWE.
 * JWS object can also be verified.
 */
final class Loader implements LoaderInterface
{
    /**
     * {@inheritdoc}
     */
    public function loadAndDecryptUsingKey($input, Object\JWKInterface $jwk, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, &$recipient_index = null)
    {
        $jwk_set = new Object\JWKSet();
        $jwk_set->addKey($jwk);

        return $this->loadAndDecrypt($input, $jwk_set, $allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, $recipient_index);
    }

    /**
     * {@inheritdoc}
     */
    public function loadAndDecryptUsingKeySet($input, Object\JWKSetInterface $jwk_set, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, &$recipient_index = null)
    {
        return $this->loadAndDecrypt($input, $jwk_set, $allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, $recipient_index);
    }

    /**
     * {@inheritdoc}
     */
    public function loadAndVerifySignatureUsingKey($input, Object\JWKInterface $jwk, array $allowed_algorithms, &$signature_index = null)
    {
        $jwk_set = new Object\JWKSet();
        $jwk_set->addKey($jwk);

        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $signature_index);
    }

    /**
     * {@inheritdoc}
     */
    public function loadAndVerifySignatureUsingKeySet($input, Object\JWKSetInterface $jwk_set, array $allowed_algorithms, &$signature_index = null)
    {
        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, null, $signature_index);
    }

    /**
     * {@inheritdoc}
     */
    public function loadAndVerifySignatureUsingKeyAndDetachedPayload($input, Object\JWKInterface $jwk, array $allowed_algorithms, $detached_payload, &$signature_index = null)
    {
        $jwk_set = new Object\JWKSet();
        $jwk_set->addKey($jwk);

        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $signature_index);
    }

    /**
     * {@inheritdoc}
     */
    public function loadAndVerifySignatureUsingKeySetAndDetachedPayload($input, Object\JWKSetInterface $jwk_set, array $allowed_algorithms, $detached_payload, &$signature_index = null)
    {
        return $this->loadAndVerifySignature($input, $jwk_set, $allowed_algorithms, $detached_payload, $signature_index);
    }

    /**
     * @param string                       $input
     * @param \Jose\Object\JWKSetInterface $jwk_set
     * @param array                        $allowed_key_encryption_algorithms
     * @param array                        $allowed_content_encryption_algorithms
     * @param null|int                     $recipient_index
     *
     * @return \Jose\Object\JWEInterface
     */
    private function loadAndDecrypt($input, Object\JWKSetInterface $jwk_set, array $allowed_key_encryption_algorithms, array $allowed_content_encryption_algorithms, &$recipient_index = null)
    {
        $jwt = $this->load($input);
        Assertion::isInstanceOf($jwt, Object\JWEInterface::class, 'The input is not a valid JWE');
        $decrypted = Decrypter::createDecrypter($allowed_key_encryption_algorithms, $allowed_content_encryption_algorithms, ['DEF', 'ZLIB', 'GZ']);

        $decrypted->decryptUsingKeySet($jwt, $jwk_set, $recipient_index);

        return $jwt;
    }

    /**
     * @param string                       $input
     * @param \Jose\Object\JWKSetInterface $jwk_set
     * @param array                        $allowed_algorithms
     * @param string|null                  $detached_payload
     * @param null|int                     $signature_index
     *
     * @return \Jose\Object\JWSInterface
     */
    private function loadAndVerifySignature($input, Object\JWKSetInterface $jwk_set, array $allowed_algorithms, $detached_payload = null, &$signature_index = null)
    {
        $jwt = $this->load($input);
        Assertion::isInstanceOf($jwt, Object\JWSInterface::class, 'The input is not a valid JWS.');
        $verifier = Verifier::createVerifier($allowed_algorithms);

        $verifier->verifyWithKeySet($jwt, $jwk_set, $detached_payload, $signature_index);

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function load($input)
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
    private function convert($input)
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
     * @param $input
     *
     * @return array
     */
    private function fromFlattenedSerializationRecipientToSerialization($input)
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
     * @param $input
     *
     * @return array
     */
    private function fromFlattenedSerializationSignatureToSerialization($input)
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
    private function fromCompactSerializationToSerialization($input)
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
    private function fromCompactSerializationRecipientToSerialization(array $parts)
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
    private function fromCompactSerializationSignatureToSerialization(array $parts)
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
