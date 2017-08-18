<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature;

use Base64Url\Base64Url;
use Jose\Component\Core\JWTInterface;

/**
 * Class JWS.
 */
final class JWS implements JWTInterface
{
    /**
     * @var bool
     */
    private $isPayloadDetached = false;

    /**
     * @var string|null
     */
    private $encodedPayload = null;

    /**
     * @var Signature[]
     */
    private $signatures = [];

    /**
     * @var string|null
     */
    private $payload = null;

    /**
     * JWS constructor.
     *
     * @param string|null $payload
     * @param string|null $encodedPayload
     * @param bool        $isPayloadDetached
     */
    private function __construct(?string $payload = null, ?string $encodedPayload = null, bool $isPayloadDetached = false)
    {
        $this->payload = $payload;
        $this->encodedPayload = $encodedPayload;
        $this->isPayloadDetached = $isPayloadDetached;
    }

    /**
     * @param string|null $payload
     * @param bool        $isPayloadDetached
     *
     * @return JWS
     */
    public static function create(?string $payload = null, bool $isPayloadDetached = false): JWS
    {
        return new self($payload, null, $isPayloadDetached);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload(): ?string
    {
        return $this->payload;
    }

    /**
     * @param string $payload
     *
     * @return JWS
     */
    public function withPayload(string $payload): JWS
    {
        $jwt = clone $this;
        $jwt->payload = $payload;

        return $jwt;
    }

    /**
     * @return bool
     */
    public function isPayloadDetached(): bool
    {
        return $this->isPayloadDetached;
    }

    /**
     * @return JWS
     */
    public function withDetachedPayload(): JWS
    {
        $jwt = clone $this;
        $jwt->isPayloadDetached = true;

        return $jwt;
    }

    /**
     * @return JWS
     */
    public function withAttachedPayload(): JWS
    {
        $jwt = clone $this;
        $jwt->isPayloadDetached = false;

        return $jwt;
    }

    /**
     * {@inheritdoc}
     */
    public function withEncodedPayload(string $encoded_payload): JWS
    {
        $jwt = clone $this;
        $jwt->encodedPayload = $encoded_payload;

        return $jwt;
    }

    /**
     * @param Signature $signature
     *
     * @return string|null
     */
    public function getEncodedPayload(Signature $signature): ?string
    {
        if (true === $this->isPayloadDetached()) {
            return null;
        }
        if (null !== $this->encodedPayload) {
            return $this->encodedPayload;
        }
        $payload = $this->getPayload();

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
    public function getSignature(int $id): Signature
    {
        if (isset($this->signatures[$id])) {
            return $this->signatures[$id];
        }

        throw new \InvalidArgumentException('The signature does not exist.');
    }

    /**
     * @param string      $signature
     * @param string|null $encoded_protected_headers
     * @param array       $headers
     *
     * @return JWS
     */
    public function addSignature(string $signature, ?string $encoded_protected_headers, array $headers = []): JWS
    {
        $jws = clone $this;
        $jws->signatures[] = Signature::create($signature, $encoded_protected_headers, $headers);

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
        if (!empty($signature->getHeaders())) {
            throw new \LogicException('The signature contains unprotected headers and cannot be converted into compact JSON.');
        }
        if (!$this->isPayloadEncoded($signature) && !empty($this->getEncodedPayload($signature))) {
            throw new \LogicException('Unable to convert the JWS with non-encoded payload.');
        }

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
     * @return string
     */
    public function toJSON(): string
    {
        if (0 === $this->countSignatures()) {
            throw new \LogicException('No signature.');
        }

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
                if ($is_encoded !== $this->isPayloadEncoded($signature)) {
                    throw new \LogicException('Foreign payload encoding detected. The JWS cannot be converted.');
                }
            }
        }
    }
}
