<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature\Object;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Component\Core\JWKInterface;
use Jose\Component\Core\JWT;
use Jose\Component\Core\JWTInterface;

/**
 * Class JWS.
 */
final class JWS implements JWTInterface
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
     * @var Signature[]
     */
    private $signatures = [];

    /**
     * @return bool
     */
    public function isPayloadDetached(): bool
    {
        return $this->is_payload_detached;
    }

    /**
     * @return JWTInterface
     */
    public function withDetachedPayload(): JWTInterface
    {
        $jwt = clone $this;
        $jwt->is_payload_detached = true;

        return $jwt;
    }

    /**
     * @return JWTInterface
     */
    public function withAttachedPayload(): JWTInterface
    {
        $jwt = clone $this;
        $jwt->is_payload_detached = false;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withEncodedPayload(string $encoded_payload): JWTInterface
    {
        $jwt = clone $this;
        $jwt->encoded_payload = $encoded_payload;

        return $jwt;
    }

    /**
     * @param Signature $signature
     *
     *
     * @return string|null
     */
    public function getEncodedPayload(Signature $signature): ?string
    {
        if (true === $this->isPayloadDetached()) {
            return null;
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
     * Returns the signature associated with the JWS.
     *
     * @return Signature[]
     */
    public function getSignatures(): array
    {
        return $this->signatures;
    }

    /**
     * @param int $id
     *
     * @return Signature
     */
    public function &getSignature(int $id): Signature
    {
        if (isset($this->signatures[$id])) {
            return $this->signatures[$id];
        }
        throw new \InvalidArgumentException('The signature does not exist.');
    }

    /**
     * @param JWKInterface $signature_key
     * @param array                     $protected_headers
     * @param array                     $headers
     *
     * @return JWS
     */
    public function addSignatureInformation(JWKInterface $signature_key, array $protected_headers, array $headers = []): JWS
    {
        $jws = clone $this;
        $jws->signatures[] = Signature::createSignature($signature_key, $protected_headers, $headers);

        return $jws;
    }

    /**
     * @param string      $signature
     * @param string|null $encoded_protected_headers
     * @param array       $headers
     *
     * @return JWS
     */
    public function addSignatureFromLoadedData(string $signature, ?string $encoded_protected_headers, array $headers): JWS
    {
        $jws = clone $this;
        $jws->signatures[] = Signature::createSignatureFromLoadedData($signature, $encoded_protected_headers, $headers);

        return $jws;
    }

    /**
     * Returns the number of signature associated with the JWS.
     *
     *
     * @return int
     */
    public function countSignatures(): int
    {
        return count($this->signatures);
    }

    /**
     * @param int $id
     *
     * @return string
     */
    public function toCompactJSON(int $id): string
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
     * @param int $id
     *
     * @return string
     */
    public function toFlattenedJSON(int $id): string
    {
        $signature = $this->getSignature($id);

        $data = [];
        $values = [
            'payload'   => $this->getEncodedPayload($signature),
            'protected' => $signature->getEncodedProtectedHeaders(),
            'header'    => $signature->getHeaders(),
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
     * @return string
     */
    public function toJSON(): string
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
                'header'    => $signature->getHeaders(),
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
     * @param Signature $signature
     *
     * @return bool
     */
    private function isPayloadEncoded(Signature $signature): bool
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
