<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

use Assert\Assertion;
use Base64Url\Base64Url;

/**
 * Class JWS.
 */
final class JWS implements JWSInterface
{
    use JWT;

    /**
     * @var bool
     */
    private $is_payload_detached = false;

    /**
     * @var string|null
     */
    private $encoded_payload = null;

    /**
     * @var \Jose\Object\SignatureInterface[]
     */
    private $signatures = [];

    /**
     * {@inheritdoc}
     */
    public function isPayloadDetached()
    {
        return $this->is_payload_detached;
    }

    /**
     * {@inheritdoc}
     */
    public function withDetachedPayload()
    {
        $jwt = clone $this;
        $jwt->is_payload_detached = true;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withAttachedPayload()
    {
        $jwt = clone $this;
        $jwt->is_payload_detached = false;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withEncodedPayload($encoded_payload)
    {
        $jwt = clone $this;
        $jwt->encoded_payload = $encoded_payload;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function getEncodedPayload(SignatureInterface $signature)
    {
        if (true === $this->isPayloadDetached()) {
            return;
        }
        if (null !== $this->encoded_payload) {
            return $this->encoded_payload;
        }
        $payload = $this->getPayload();
        if (!is_string($payload)) {
            $payload = json_encode($payload);
        }
        Assertion::notNull($payload, 'Unsupported payload.');

        return $this->isPayloadEncoded($signature) ? Base64Url::encode($payload) : $payload;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignatures()
    {
        return $this->signatures;
    }

    /**
     * {@inheritdoc}
     */
    public function &getSignature($id)
    {
        if (isset($this->signatures[$id])) {
            return $this->signatures[$id];
        }

        throw new \InvalidArgumentException('The signature does not exist.');
    }

    /**
     * {@inheritdoc}
     */
    public function addSignatureInformation(JWKInterface $signature_key, array $protected_headers, array $headers = [])
    {
        $jws = clone $this;
        $jws->signatures[] = Signature::createSignature($signature_key, $protected_headers, $headers);

        return $jws;
    }

    /**
     * {@inheritdoc}
     */
    public function addSignatureFromLoadedData($signature, $encoded_protected_headers, array $headers)
    {
        $jws = clone $this;
        $jws->signatures[] = Signature::createSignatureFromLoadedData($signature, $encoded_protected_headers, $headers);

        return $jws;
    }

    /**
     * {@inheritdoc}
     */
    public function countSignatures()
    {
        return count($this->signatures);
    }

    /**
     * {@inheritdoc}
     */
    public function toCompactJSON($id)
    {
        $signature = $this->getSignature($id);

        Assertion::true(
            empty($signature->getHeaders()),
            'The signature contains unprotected headers and cannot be converted into compact JSON'
        );
        Assertion::true($this->isPayloadEncoded($signature) || empty($this->getEncodedPayload($signature)), 'Unable to convert the JWS with non-encoded payload.');

        return sprintf(
            '%s.%s.%s',
            $signature->getEncodedProtectedHeaders(),
            $this->getEncodedPayload($signature),
            Base64Url::encode($signature->getSignature())
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toFlattenedJSON($id)
    {
        $signature = $this->getSignature($id);

        $data = [];
        $values = [
            'payload' => $this->getEncodedPayload($signature),
            'protected' => $signature->getEncodedProtectedHeaders(),
            'header' => $signature->getHeaders(),
        ];

        foreach ($values as $key => $value) {
            if (!empty($value)) {
                $data[$key] = $value;
            }
        }
        $data['signature'] = Base64Url::encode($signature->getSignature());

        return json_encode($data);
    }

    /**
     * {@inheritdoc}
     */
    public function toJSON()
    {
        Assertion::greaterThan($this->countSignatures(), 0, 'No signature.');

        $data = [];
        $this->checkPayloadEncoding();

        if (false === $this->isPayloadDetached()) {
            $data['payload'] = $this->getEncodedPayload($this->getSignature(0));
        }

        $data['signatures'] = [];
        foreach ($this->getSignatures() as $signature) {
            $tmp = ['signature' => Base64Url::encode($signature->getSignature())];
            $values = [
                'protected' => $signature->getEncodedProtectedHeaders(),
                'header' => $signature->getHeaders(),
            ];

            foreach ($values as $key => $value) {
                if (!empty($value)) {
                    $tmp[$key] = $value;
                }
            }
            $data['signatures'][] = $tmp;
        }

        return json_encode($data);
    }

    /**
     * @param \Jose\Object\SignatureInterface $signature
     *
     * @return bool
     */
    private function isPayloadEncoded(SignatureInterface $signature)
    {
        return !$signature->hasProtectedHeader('b64') || true === $signature->getProtectedHeader('b64');
    }

    private function checkPayloadEncoding()
    {
        $is_encoded = null;
        foreach ($this->getSignatures() as $signature) {
            if (null === $is_encoded) {
                $is_encoded = $this->isPayloadEncoded($signature);
            }
            if (false === $this->isPayloadDetached()) {
                Assertion::eq($is_encoded, $this->isPayloadEncoded($signature), 'Foreign payload encoding detected. The JWS cannot be converted.');
            }
        }
    }
}
