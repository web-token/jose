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

/**
 * Class EncryptionInstruction.
 */
final class Recipient implements RecipientInterface
{
    /**
     * @var array
     */
    private $headers = [];

    /**
     * @var null|string
     */
    private $encrypted_key = null;

    /**
     * @var \Jose\Object\JWKInterface
     */
    private $recipient_key = null;

    /**
     * {@inheritdoc}
     */
    public static function createRecipientFromLoadedJWE(array $headers, $encrypted_key)
    {
        $recipient = new self();
        $recipient->headers = $headers;
        $recipient->encrypted_key = $encrypted_key;

        return $recipient;
    }

    /**
     * {@inheritdoc}
     */
    public static function createRecipient(JWKInterface $recipient_key, array $headers = [])
    {
        $recipient = new self();
        $recipient->headers = $headers;
        $recipient->recipient_key = $recipient_key;

        return $recipient;
    }

    /**
     * {@inheritdoc}
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * {@inheritdoc}
     */
    public function getHeader($key)
    {
        if ($this->hasHeader($key)) {
            return $this->headers[$key];
        }

        throw new \InvalidArgumentException(sprintf('The header "%s" does not exist.', $key));
    }

    /**
     * {@inheritdoc}
     */
    public function hasHeader($key)
    {
        return array_key_exists($key, $this->headers);
    }

    /**
     * {@inheritdoc}
     */
    public function getEncryptedKey()
    {
        return $this->encrypted_key;
    }

    /**
     * {@inheritdoc}
     */
    public function getRecipientKey()
    {
        return $this->recipient_key;
    }
}
