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

namespace Jose\Component\Encryption;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Component\Core\JWTInterface;

/**
 * Class JWE.
 */
final class JWE implements JWTInterface
{
    /**
     * @var Recipient[]
     */
    private $recipients = [];

    /**
     * @var string|null
     */
    private $ciphertext = null;

    /**
     * @var string|null
     */
    private $iv = null;

    /**
     * @var string|null
     */
    private $aad = null;

    /**
     * @var string|null
     */
    private $tag = null;

    /**
     * @var array
     */
    private $sharedHeaders = [];

    /**
     * @var array
     */
    private $sharedProtectedHeaders = [];

    /**
     * @var string|null
     */
    private $encodedSharedProtectedHeaders = null;

    /**
     * @var mixed|null
     */
    private $payload = null;

    /**
     * JWE constructor.
     *
     * @param string      $ciphertext
     * @param null|string $iv
     * @param null|string $aad
     * @param null|string $tag
     * @param array       $sharedHeaders
     * @param array       $sharedProtectedHeaders
     * @param null|string $encodedSharedProtectedHeaders
     * @param array       $recipients
     */
    private function __construct(string $ciphertext, ?string $iv = null, ?string $aad = null, ?string $tag = null, array $sharedHeaders = [], array $sharedProtectedHeaders = [], ?string $encodedSharedProtectedHeaders = null, array $recipients = [])
    {
        $this->ciphertext = $ciphertext;
        $this->iv = $iv;
        $this->aad = $aad;
        $this->tag = $tag;
        $this->sharedHeaders = $sharedHeaders;
        $this->sharedProtectedHeaders = $sharedProtectedHeaders;
        $this->encodedSharedProtectedHeaders = $encodedSharedProtectedHeaders;
        $this->recipients = $recipients;
    }

    /**
     * @param string      $ciphertext
     * @param null|string $iv
     * @param null|string $aad
     * @param null|string $tag
     * @param array       $sharedHeaders
     * @param array       $sharedProtectedHeaders
     * @param null|string $encodedSharedProtectedHeaders
     * @param array       $recipients
     *
     * @return JWE
     */
    public static function create(string $ciphertext, ?string $iv = null, ?string $aad = null, ?string $tag = null, array $sharedHeaders = [], array $sharedProtectedHeaders = [], ?string $encodedSharedProtectedHeaders = null, array $recipients = []): JWE
    {
        return new self($ciphertext, $iv, $aad, $tag, $sharedHeaders, $sharedProtectedHeaders, $encodedSharedProtectedHeaders, $recipients);
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param $payload
     *
     * @return JWE
     */
    public function withPayload($payload): JWE
    {
        $clone = clone $this;
        $clone->payload = $payload;

        return $clone;
    }

    /**
     * {@inheritdoc}
     */
    public function getClaim(string $key)
    {
        if ($this->hasClaim($key)) {
            return $this->payload[$key];
        }
        throw new \InvalidArgumentException(sprintf('The payload does not contain claim "%s".', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function getClaims(): array
    {
        if (!$this->hasClaims()) {
            throw new \InvalidArgumentException('The payload does not contain claims.');
        }

        return $this->payload;
    }

    /**
     * {@inheritdoc}
     */
    public function hasClaim(string $key): bool
    {
        return $this->hasClaims() && array_key_exists($key, $this->payload);
    }

    /**
     * {@inheritdoc}
     */
    public function hasClaims(): bool
    {
        return is_array($this->payload);
    }

    /**
     * Returns the number of recipients associated with the JWS.
     *
     * @return int
     */
    public function countRecipients(): int
    {
        return count($this->recipients);
    }

    /**
     * @return bool
     */
    public function isEncrypted(): bool
    {
        return null !== $this->getCiphertext();
    }

    /**
     * Returns the recipients associated with the JWS.
     *
     * @return Recipient[]
     */
    public function getRecipients(): array
    {
        return $this->recipients;
    }

    /**
     * @param int $id
     *
     * @return Recipient
     */
    public function getRecipient(int $id): Recipient
    {
        Assertion::keyExists($this->recipients, $id, 'The recipient does not exist.');

        return $this->recipients[$id];
    }

    /**
     * @return string|null The cyphertext
     */
    public function getCiphertext(): ?string
    {
        return $this->ciphertext;
    }

    /**
     * @return string|null
     */
    public function getAAD(): ?string
    {
        return $this->aad;
    }

    /**
     * @return string|null
     */
    public function getIV(): ?string
    {
        return $this->iv;
    }

    /**
     * @return string|null
     */
    public function getTag(): ?string
    {
        return $this->tag;
    }

    /**
     * @return string
     */
    public function getEncodedSharedProtectedHeaders(): string
    {
        return $this->encodedSharedProtectedHeaders ?? '';
    }

    /**
     * @return array
     */
    public function getSharedProtectedHeaders(): array
    {
        return $this->sharedProtectedHeaders;
    }

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedProtectedHeader(string $key)
    {
        if ($this->hasSharedProtectedHeader($key)) {
            return $this->sharedProtectedHeaders[$key];
        }
        throw new \InvalidArgumentException(sprintf('The shared protected header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedProtectedHeader(string $key): bool
    {
        return array_key_exists($key, $this->sharedProtectedHeaders);
    }

    /**
     * @return array
     */
    public function getSharedHeaders(): array
    {
        return $this->sharedHeaders;
    }

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedHeader(string $key)
    {
        if ($this->hasSharedHeader($key)) {
            return $this->sharedHeaders[$key];
        }
        throw new \InvalidArgumentException(sprintf('The shared header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedHeader(string $key): bool
    {
        return array_key_exists($key, $this->sharedHeaders);
    }

    /**
     * @param int $id
     *
     * @return string
     */
    public function toCompactJSON(int $id): string
    {
        $recipient = $this->getRecipient($id);

        $this->checkHasNoAAD();
        $this->checkHasSharedProtectedHeaders();
        $this->checkRecipientHasNoHeaders($id);

        return sprintf(
            '%s.%s.%s.%s.%s',
            $this->getEncodedSharedProtectedHeaders(),
            Base64Url::encode(null === $recipient->getEncryptedKey() ? '' : $recipient->getEncryptedKey()),
            Base64Url::encode(null === $this->getIV() ? '' : $this->getIV()),
            Base64Url::encode($this->getCiphertext()),
            Base64Url::encode(null === $this->getTag() ? '' : $this->getTag())
        );
    }

    private function checkHasNoAAD()
    {
        Assertion::true(empty($this->getAAD()), 'This JWE has AAD and cannot be converted into Compact JSON.');
    }

    /**
     * @param int $id
     */
    private function checkRecipientHasNoHeaders(int $id)
    {
        Assertion::true(
            empty($this->getSharedHeaders()) && empty($this->getRecipient($id)->getHeaders()),
            'This JWE has shared headers or recipient headers and cannot be converted into Compact JSON.'
        );
    }

    private function checkHasSharedProtectedHeaders()
    {
        Assertion::notEmpty(
            $this->getSharedProtectedHeaders(),
            'This JWE does not have shared protected headers and cannot be converted into Compact JSON.'
        );
    }

    /**
     * @param int $id
     *
     * @return string
     */
    public function toFlattenedJSON(int $id): string
    {
        $recipient = $this->getRecipient($id);

        $json = $this->getJSONBase();

        if (!empty($recipient->getHeaders())) {
            $json['header'] = $recipient->getHeaders();
        }
        if (!empty($recipient->getEncryptedKey())) {
            $json['encrypted_key'] = Base64Url::encode($recipient->getEncryptedKey());
        }

        return json_encode($json);
    }

    /**
     * @return string
     */
    public function toJSON(): string
    {
        $json = $this->getJSONBase();
        $json['recipients'] = [];

        foreach ($this->getRecipients() as $recipient) {
            $temp = [];
            if (!empty($recipient->getHeaders())) {
                $temp['header'] = $recipient->getHeaders();
            }
            if (!empty($recipient->getEncryptedKey())) {
                $temp['encrypted_key'] = Base64Url::encode($recipient->getEncryptedKey());
            }
            $json['recipients'][] = $temp;
        }

        return json_encode($json);
    }

    /**
     * @return array
     */
    private function getJSONBase(): array
    {
        $json = [
            'ciphertext' => Base64Url::encode($this->getCiphertext()),
        ];
        if (null !== $this->getIV()) {
            $json['iv'] = Base64Url::encode($this->getIV());
        }
        if (null !== $this->getTag()) {
            $json['tag'] = Base64Url::encode($this->getTag());
        }
        if (null !== $this->getAAD()) {
            $json['aad'] = Base64Url::encode($this->getAAD());
        }
        if (!empty($this->getSharedProtectedHeaders())) {
            $json['protected'] = $this->getEncodedSharedProtectedHeaders();
        }
        if (!empty($this->getSharedHeaders())) {
            $json['unprotected'] = $this->getSharedHeaders();
        }

        return $json;
    }
}
