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

use Base64Url\Base64Url;
use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\KeyChecker;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Compression\CompressionInterface;
use Jose\Component\Encryption\Compression\CompressionManager;

final class JWEBuilder
{
    /**
     * @var mixed
     */
    private $payload;

    /**
     * @var string|null
     */
    private $aad;

    /**
     * @var array
     */
    private $recipients = [];

    /**
     * @var JWAManager
     */
    private $keyEncryptionAlgorithmManager;

    /**
     * @var JWAManager
     */
    private $contentEncryptionAlgorithmManager;

    /**
     * @var CompressionManager
     */
    private $compressionManager;

    /**
     * @var array
     */
    private $sharedProtectedHeaders = [];

    /**
     * @var array
     */
    private $sharedHeaders = [];

    /**
     * @var null|CompressionInterface
     */
    private $compressionMethod = null;

    /**
     * @var null|ContentEncryptionAlgorithmInterface
     */
    private $contentEncryptionAlgorithm = null;

    /**
     * @var null|string
     */
    private $keyManagementMode = null;

    /**
     * JWEBuilder constructor.
     *
     * @param JWAManager         $keyEncryptionAlgorithmManager
     * @param JWAManager         $contentEncryptionAlgorithmManager
     * @param CompressionManager $compressionManager
     */
    public function __construct(JWAManager $keyEncryptionAlgorithmManager, JWAManager $contentEncryptionAlgorithmManager, CompressionManager $compressionManager)
    {
        $this->keyEncryptionAlgorithmManager = $keyEncryptionAlgorithmManager;
        $this->contentEncryptionAlgorithmManager = $contentEncryptionAlgorithmManager;
        $this->compressionManager = $compressionManager;
    }

    /**
     * @return string[]
     */
    public function getSupportedKeyEncryptionAlgorithms(): array
    {
        return $this->keyEncryptionAlgorithmManager->list();
    }

    /**
     * @return string[]
     */
    public function getSupportedContentEncryptionAlgorithms(): array
    {
        return $this->contentEncryptionAlgorithmManager->list();
    }

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods(): array
    {
        return $this->compressionManager->list();
    }

    /**
     * @param mixed $payload
     *
     * @return JWEBuilder
     */
    public function withPayload($payload): JWEBuilder
    {
        $clone = clone $this;
        $clone->payload = $payload;

        return $clone;
    }

    /**
     * @param string $aad
     *
     * @return JWEBuilder
     */
    public function withAAD(string $aad): JWEBuilder
    {
        $clone = clone $this;
        $clone->aad = $aad;

        return $clone;
    }

    /**
     * @param array $sharedProtectedHeaders
     *
     * @return JWEBuilder
     */
    public function withSharedProtectedHeaders(array $sharedProtectedHeaders): JWEBuilder
    {
        $clone = clone $this;
        $clone->sharedProtectedHeaders = $sharedProtectedHeaders;

        return $clone;
    }

    /**
     * @param array $sharedHeaders
     *
     * @return JWEBuilder
     */
    public function withSharedHeaders(array $sharedHeaders): JWEBuilder
    {
        $clone = clone $this;
        $clone->sharedHeaders = $sharedHeaders;

        return $clone;
    }

    /**
     * @param JWK   $recipientKey
     * @param array $recipientHeaders
     *
     * @return JWEBuilder
     */
    public function addRecipient(JWK $recipientKey, array $recipientHeaders = []): JWEBuilder
    {
        $clone = clone $this;
        $completeHeaders = array_merge($clone->sharedHeaders, $recipientHeaders, $clone->sharedProtectedHeaders);
        $clone->checkContentEncryptionAlgorithm($completeHeaders);
        $keyEncryptionAlgorithm = $clone->getKeyEncryptionAlgorithm($completeHeaders);
        $clone->checkKeys($keyEncryptionAlgorithm, $clone->contentEncryptionAlgorithm, $recipientKey);
        $clone->recipients[] = [
            'key' => $recipientKey,
            'headers' => $recipientHeaders,
            'key_encryption_algorithm' => $keyEncryptionAlgorithm,
        ];

        return $clone;
    }

    /**
     * @return JWE
     */
    public function build(): JWE
    {
        if (0 === count($this->recipients)) {
            throw new \LogicException('No recipient.');
        }

        $additionalHeaders = [];
        $this->contentEncryptionAlgorithm = $this->getContentEncryptionAlgorithm($jwe);
        $this->compressionMethod = $this->getCompressionMethod($jwe);
        $this->keyManagementMode = $this->getKeyManagementMode($jwe);
        $cek = $this->determineCEK($jwe, $contentEncryptionAlgorithm, $keyManagementMode, $additionalHeaders);

        foreach ($this->recipients as $recipient) {
            $this->processRecipient($jwe, $jwe->getRecipient($i), $cek, $contentEncryptionAlgorithm, $additionalHeaders);
        }

        $iv_size = $contentEncryptionAlgorithm->getIVSize();
        $iv = $this->createIV($iv_size);

        $this->encryptJWE($jwe, $contentEncryptionAlgorithm, $cek, $iv, $compressionMethod);

        return JWE::createFromLoadedData($this->payload, $this->sharedProtectedHeaders, $this->sharedHeaders, $this->aad);
    }

    /**
     * @param array $completeHeaders
     */
    private function checkContentEncryptionAlgorithm(array $completeHeaders): void
    {
        $contentEncryptionAlgorithm = $this->getContentEncryptionAlgorithm($completeHeaders);
        if (null === $this->contentEncryptionAlgorithm) {
            $this->contentEncryptionAlgorithm = $contentEncryptionAlgorithm;
        } elseif ($contentEncryptionAlgorithm->name() !== $this->contentEncryptionAlgorithm->name()) {
            throw new \InvalidArgumentException('Inconsistent content encryption algorithm');
        }
    }

    /**
     * @param JWE                                 $jwe
     * @param Recipient                           $recipient
     * @param string                              $cek
     * @param ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm
     * @param array                               $additionalHeaders
     */
    private function processRecipient(JWE $jwe, Recipient &$recipient, $cek, ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm, array &$additionalHeaders)
    {
        if (null === $recipient->getRecipientKey()) {
            return;
        }
        $completeHeaders = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $recipient->getHeaders());
        $keyEncryptionAlgorithm = $this->getKeyEncryptionAlgorithm($completeHeaders);
        $encrypted_content_encryption_key = $this->getEncryptedKey($completeHeaders, $cek, $keyEncryptionAlgorithm, $contentEncryptionAlgorithm, $additionalHeaders, $recipient->getRecipientKey());
        $recipient_headers = $recipient->getHeaders();
        if (!empty($additionalHeaders) && 1 !== $jwe->countRecipients()) {
            $recipient_headers = array_merge($recipient_headers, $additionalHeaders);
            $additionalHeaders = [];
        }

        $recipient = Recipient::createRecipientFromLoadedJWE($recipient_headers, $encrypted_content_encryption_key);
    }

    /**
     * @param JWE                                 $jwe
     * @param ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm
     * @param string                              $cek
     * @param string                              $iv
     * @param CompressionInterface|null           $compressionMethod
     */
    private function encryptJWE(JWE &$jwe, ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm, $cek, $iv, CompressionInterface $compressionMethod = null)
    {
        if (!empty($jwe->getSharedProtectedHeaders())) {
            $jwe = $jwe->withEncodedSharedProtectedHeaders(Base64Url::encode(json_encode($jwe->getSharedProtectedHeaders())));
        }

        $tag = null;
        $payload = $this->preparePayload($jwe->getPayload(), $compressionMethod);
        $aad = null === $jwe->getAAD() ? null : Base64Url::encode($jwe->getAAD());
        $ciphertext = $contentEncryptionAlgorithm->encryptContent($payload, $cek, $iv, $aad, $jwe->getEncodedSharedProtectedHeaders(), $tag);
        $jwe = $jwe->withCiphertext($ciphertext);
        $jwe = $jwe->withIV($iv);

        if (null !== $tag) {
            $jwe = $jwe->withTag($tag);
        }
    }

    /**
     * @param string                    $payload
     * @param CompressionInterface|null $compressionMethod
     *
     * @return string
     */
    private function preparePayload($payload, CompressionInterface $compressionMethod = null)
    {
        $prepared = is_string($payload) ? $payload : json_encode($payload);
        if (null === $prepared) {
            throw new \RuntimeException('The payload is empty or cannot encoded into JSON.');
        }

        if (null === $compressionMethod) {
            return $prepared;
        }
        $compressedPayload = $compressionMethod->compress($prepared);
        if (null === $compressedPayload) {
            throw new \RuntimeException('The payload cannot be compressed.');
        }

        return $compressedPayload;
    }

    /**
     * @param array                               $completeHeaders
     * @param string                              $cek
     * @param KeyEncryptionAlgorithmInterface     $keyEncryptionAlgorithm
     * @param ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm
     * @param JWK                                 $recipientKey
     * @param array                               $additionalHeaders
     *
     * @return string|null
     */
    private function getEncryptedKey(array $completeHeaders, $cek, KeyEncryptionAlgorithmInterface $keyEncryptionAlgorithm, ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm, array &$additionalHeaders, JWK $recipientKey)
    {
        if ($keyEncryptionAlgorithm instanceof KeyEncryptionInterface) {
            return $this->getEncryptedKeyFromKeyEncryptionAlgorithm($completeHeaders, $cek, $keyEncryptionAlgorithm, $recipientKey, $additionalHeaders);
        } elseif ($keyEncryptionAlgorithm instanceof KeyWrappingInterface) {
            return $this->getEncryptedKeyFromKeyWrappingAlgorithm($completeHeaders, $cek, $keyEncryptionAlgorithm, $recipientKey, $additionalHeaders);
        } elseif ($keyEncryptionAlgorithm instanceof KeyAgreementWrappingInterface) {
            return $this->getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm($completeHeaders, $cek, $keyEncryptionAlgorithm, $contentEncryptionAlgorithm, $additionalHeaders, $recipientKey);
        }
        throw new \InvalidArgumentException('Unsupported key encryption algorithm.');
    }

    /**
     * @param array                               $completeHeaders
     * @param string                              $cek
     * @param KeyAgreementWrappingInterface       $keyEncryptionAlgorithm
     * @param ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm
     * @param array                               $additionalHeaders
     * @param JWK                                 $recipientKey
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm(array $completeHeaders, $cek, KeyAgreementWrappingInterface $keyEncryptionAlgorithm, ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm, array &$additionalHeaders, JWK $recipientKey)
    {
        $jwt_cek = $keyEncryptionAlgorithm->wrapAgreementKey($recipientKey, $cek, $contentEncryptionAlgorithm->getCEKSize(), $completeHeaders, $additionalHeaders);

        return $jwt_cek;
    }

    /**
     * @param array                  $completeHeaders
     * @param string                 $cek
     * @param KeyEncryptionInterface $keyEncryptionAlgorithm
     * @param JWK                    $recipientKey
     * @param array                  $additionalHeaders
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyEncryptionAlgorithm(array $completeHeaders, $cek, KeyEncryptionInterface $keyEncryptionAlgorithm, JWK $recipientKey, array &$additionalHeaders)
    {
        return $keyEncryptionAlgorithm->encryptKey($recipientKey, $cek, $completeHeaders, $additionalHeaders);
    }

    /**
     * @param array                $completeHeaders
     * @param string               $cek
     * @param KeyWrappingInterface $keyEncryptionAlgorithm
     * @param JWK                  $recipientKey
     * @param array                $additionalHeaders
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyWrappingAlgorithm(array $completeHeaders, $cek, KeyWrappingInterface $keyEncryptionAlgorithm, JWK $recipientKey, &$additionalHeaders)
    {
        return $keyEncryptionAlgorithm->wrapKey($recipientKey, $cek, $completeHeaders, $additionalHeaders);
    }

    /**
     * @param KeyEncryptionAlgorithmInterface     $keyEncryptionAlgorithm
     * @param ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm
     * @param JWK                                 $recipientKey
     */
    private function checkKeys(KeyEncryptionAlgorithmInterface $keyEncryptionAlgorithm, ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm, JWK $recipientKey)
    {
        KeyChecker::checkKeyUsage($recipientKey, 'encryption');
        if ('dir' !== $keyEncryptionAlgorithm->name()) {
            KeyChecker::checkKeyAlgorithm($recipientKey, $keyEncryptionAlgorithm->name());
        } else {
            KeyChecker::checkKeyAlgorithm($recipientKey, $contentEncryptionAlgorithm->name());
        }
    }

    /**
     * @param JWE                                 $jwe
     * @param ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm
     * @param array                               $additionalHeaders
     *
     * @return string
     */
    private function determineCEK(JWE $jwe, ContentEncryptionAlgorithmInterface $contentEncryptionAlgorithm, array &$additionalHeaders): string
    {
        switch ($this->keyManagementMode) {
            case KeyEncryptionInterface::MODE_ENCRYPT:
            case KeyEncryptionInterface::MODE_WRAP:
                return $this->createCEK($contentEncryptionAlgorithm->getCEKSize());
            case KeyEncryptionInterface::MODE_AGREEMENT:
                if (1 !== count($this->recipients)) {
                    throw new \LogicException('Unable to encrypt for multiple recipients using key agreement algorithms.');
                }
                // Get the algorithm from the recipient directly

                //$completeHeaders = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $jwe->getRecipient(0)->getHeaders());
                //$algorithm = $this->getKeyEncryptionAlgorithm($completeHeaders);

                return $algorithm->getAgreementKey($contentEncryptionAlgorithm->getCEKSize(), $contentEncryptionAlgorithm->name(), $jwe->getRecipient(0)->getRecipientKey(), $completeHeaders, $additionalHeaders);
            case KeyEncryptionInterface::MODE_DIRECT:
                if (1 !== count($this->recipients)) {
                    throw new \LogicException('Unable to encrypt for multiple recipients using key agreement algorithms.');
                }

                Assertion::eq($jwe->getRecipient(0)->getRecipientKey()->get('kty'), 'oct', 'Wrong key type.');
                Assertion::true($jwe->getRecipient(0)->getRecipientKey()->has('k'), 'The key parameter "k" is missing.');

                return Base64Url::decode($jwe->getRecipient(0)->getRecipientKey()->get('k'));
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported key management mode "%s".', $this->keyManagementMode));
        }
    }

    /**
     * @param array $completeHeaders
     *
     * @return CompressionInterface|null
     */
    private function getCompressionMethod(array $completeHeaders): ?CompressionInterface
    {
        if (!array_key_exists('zip', $completeHeaders)) {
            return null;
        }

        return $this->compressionManager->get($completeHeaders['zip']);
    }

    /**
     * @param string $current
     * @param string $new
     *
     * @return bool
     */
    private function areKeyManagementModesCompatible(string $current, string $new): bool
    {
        $agree = KeyEncryptionAlgorithmInterface::MODE_AGREEMENT;
        $dir = KeyEncryptionAlgorithmInterface::MODE_DIRECT;
        $enc = KeyEncryptionAlgorithmInterface::MODE_ENCRYPT;
        $wrap = KeyEncryptionAlgorithmInterface::MODE_WRAP;
        $supportedKeyManagementModeCombinations = [$enc.$enc => true, $enc.$wrap => true, $wrap.$enc => true, $wrap.$wrap => true, $agree.$agree => false, $agree.$dir => false, $agree.$enc => false, $agree.$wrap => false, $dir.$agree => false, $dir.$dir => false, $dir.$enc => false, $dir.$wrap => false, $enc.$agree => false, $enc.$dir => false, $wrap.$agree => false, $wrap.$dir => false];

        if (array_key_exists($current.$new, $supportedKeyManagementModeCombinations)) {
            return $supportedKeyManagementModeCombinations[$current.$new];
        }

        return false;
    }

    /**
     * @param int $size
     *
     * @return string
     */
    private function createCEK(int $size): string
    {
        return random_bytes($size / 8);
    }

    /**
     * @param int $size
     *
     * @return string
     */
    private function createIV(int $size): string
    {
        return random_bytes($size / 8);
    }

    /**
     * @param array $completeHeaders
     *
     * @return KeyEncryptionAlgorithmInterface
     */
    private function getKeyEncryptionAlgorithm(array $completeHeaders): KeyEncryptionAlgorithmInterface
    {
        if (!array_key_exists('alg', $completeHeaders)) {
            throw new \LogicException('Parameter "alg" is missing.');
        }
        $keyEncryptionAlgorithm = $this->keyEncryptionAlgorithmManager->get($completeHeaders['alg']);
        if (!$keyEncryptionAlgorithm instanceof KeyEncryptionAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $completeHeaders['alg']));
        }

        return $keyEncryptionAlgorithm;
    }

    /**
     * @param array $completeHeaders
     *
     * @return ContentEncryptionAlgorithmInterface
     */
    private function getContentEncryptionAlgorithm(array $completeHeaders): ContentEncryptionAlgorithmInterface
    {
        if (!array_key_exists('enc', $completeHeaders)) {
            throw new \LogicException('Parameter "enc" is missing.');
        }
        $contentEncryptionAlgorithm = $this->contentEncryptionAlgorithmManager->get($completeHeaders['enc']);
        if (!$contentEncryptionAlgorithm instanceof ContentEncryptionAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The content encryption algorithm "%s" is not supported or not a content encryption algorithm instance.', $completeHeaders['alg']));
        }

        return $contentEncryptionAlgorithm;
    }
}
