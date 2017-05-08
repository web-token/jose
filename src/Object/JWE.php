<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

use Assert\Assertion;
use Base64Url\Base64Url;

/**
 * Class JWE.
 */
final class JWE implements JWTInterface
{
    use JWT;

    /**
     * @var \Jose\Object\Recipient[]
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
    private $shared_headers = [];

    /**
     * @var array
     */
    private $shared_protected_headers = [];

    /**
     * @var string|null
     */
    private $encoded_shared_protected_headers = null;

    /**
     * Returns the number of recipients associated with the JWS.
     *
     * @return int
     */
    public function countRecipients()
    {
        return count($this->recipients);
    }

    /**
     * @return bool
     */
    public function isEncrypted()
    {
        return null !== $this->getCiphertext();
    }

    /**
     * @param \Jose\Object\JWKInterface $recipient_key
     * @param array                     $recipient_headers
     *
     * @return \Jose\Object\JWE
     */
    public function addRecipientInformation(JWKInterface $recipient_key, $recipient_headers = [])
    {
        Assertion::true(null === $this->getCiphertext(), 'The JWE is encrypted. No additional recipient allowed.');
        $jwe = clone $this;
        $jwe->recipients[] = Recipient::createRecipient($recipient_key, $recipient_headers);

        return $jwe;
    }

    /**
     * @param string|null $encrypted_key
     * @param array       $recipient_headers
     *
     * @return \Jose\Object\JWE
     */
    public function addRecipientWithEncryptedKey($encrypted_key, array $recipient_headers)
    {
        $jwe = clone $this;
        $jwe->recipients[] = Recipient::createRecipientFromLoadedJWE($recipient_headers, $encrypted_key);

        return $jwe;
    }

    /**
     * Returns the recipients associated with the JWS.
     *
     * @return \Jose\Object\Recipient[]
     */
    public function getRecipients()
    {
        return $this->recipients;
    }

    /**
     * @param int $id
     *
     * @return \Jose\Object\Recipient
     */
    public function &getRecipient($id)
    {
        Assertion::keyExists($this->recipients, $id, 'The recipient does not exist.');

        return $this->recipients[$id];
    }

    /**
     * @internal
     *
     * @return string|null The cyphertext
     */
    public function getCiphertext()
    {
        return $this->ciphertext;
    }

    /**
     * @param string $ciphertext
     *
     * @internal
     *
     * @return \Jose\Object\JWE
     */
    public function withCiphertext($ciphertext)
    {
        $jwe = clone $this;
        $jwe->ciphertext = $ciphertext;

        return $jwe;
    }

    /**
     * @internal
     *
     * @return string|null
     */
    public function getAAD()
    {
        return $this->aad;
    }

    /**
     * @internal
     *
     * @param string $aad
     *
     * @return \Jose\Object\JWE
     */
    public function withAAD($aad)
    {
        $jwe = clone $this;
        $jwe->aad = $aad;

        return $jwe;
    }

    /**
     * @internal
     *
     * @return string|null
     */
    public function getIV()
    {
        return $this->iv;
    }

    /**
     * @internal
     *
     * @param string $iv
     *
     * @return \Jose\Object\JWE
     */
    public function withIV($iv)
    {
        $jwe = clone $this;
        $jwe->iv = $iv;

        return $jwe;
    }

    /**
     * @internal
     *
     * @return string|null
     */
    public function getTag()
    {
        return $this->tag;
    }

    /**
     * @internal
     *
     * @param string $tag
     *
     * @return \Jose\Object\JWE
     */
    public function withTag($tag)
    {
        $jwe = clone $this;
        $jwe->tag = $tag;

        return $jwe;
    }

    /**
     * @internal
     *
     * @return string|null
     */
    public function getEncodedSharedProtectedHeaders()
    {
        return $this->encoded_shared_protected_headers;
    }

    /**
     * @internal
     *
     * @param string $encoded_shared_protected_headers
     *
     * @return \Jose\Object\JWE
     */
    public function withEncodedSharedProtectedHeaders($encoded_shared_protected_headers)
    {
        $jwe = clone $this;
        $jwe->encoded_shared_protected_headers = $encoded_shared_protected_headers;

        return $jwe;
    }

    /**
     * @return array
     */
    public function getSharedProtectedHeaders()
    {
        return $this->shared_protected_headers;
    }

    /**
     * @param array $shared_protected_headers
     *
     * @return \Jose\Object\JWE
     */
    public function withSharedProtectedHeaders(array $shared_protected_headers)
    {
        $jwe = clone $this;
        $jwe->shared_protected_headers = $shared_protected_headers;

        return $jwe;
    }

    /**
     * @param string     $key
     * @param mixed|null $value
     *
     * @return \Jose\Object\JWE
     */
    public function withSharedProtectedHeader($key, $value)
    {
        $jwe = clone $this;
        $jwe->shared_protected_headers[$key] = $value;

        return $jwe;
    }

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedProtectedHeader($key)
    {
        if ($this->hasSharedProtectedHeader($key)) {
            return $this->shared_protected_headers[$key];
        }
        throw new \InvalidArgumentException(sprintf('The shared protected header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedProtectedHeader($key)
    {
        return array_key_exists($key, $this->shared_protected_headers);
    }

    /**
     * @param array $shared_headers
     *
     * @return \Jose\Object\JWE
     */
    public function withSharedHeaders(array $shared_headers)
    {
        $jwe = clone $this;
        $jwe->shared_headers = $shared_headers;

        return $jwe;
    }

    /**
     * @param string     $key
     * @param mixed|null $value
     *
     * @return \Jose\Object\JWE
     */
    public function withSharedHeader($key, $value)
    {
        $jwe = clone $this;
        $jwe->shared_headers[$key] = $value;

        return $jwe;
    }

    /**
     * @return array
     */
    public function getSharedHeaders()
    {
        return $this->shared_headers;
    }

    /**
     * @param string $key The key
     *
     * @return mixed|null Header value
     */
    public function getSharedHeader($key)
    {
        if ($this->hasSharedHeader($key)) {
            return $this->shared_headers[$key];
        }
        throw new \InvalidArgumentException(sprintf('The shared header "%s" does not exist.', $key));
    }

    /**
     * @param string $key The key
     *
     * @return bool
     */
    public function hasSharedHeader($key)
    {
        return array_key_exists($key, $this->shared_headers);
    }

    /**
     * @param int $id
     *
     * @return string
     */
    public function toCompactJSON($id)
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
    private function checkRecipientHasNoHeaders($id)
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
    public function toFlattenedJSON($id)
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
    public function toJSON()
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
    private function getJSONBase()
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
