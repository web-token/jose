<?php

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
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Component\Core\JWAManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Behaviour\HasKeyChecker;
use Jose\Component\Encryption\Compression\CompressionInterface;
use Jose\Component\Encryption\Compression\CompressionManager;
use Jose\Component\Encryption\JWE;
use Jose\Component\Core\JWKInterface;
use Jose\Component\Encryption\Recipient;

final class Encrypter
{
    use HasKeyChecker;

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
     * @return CompressionManager
     */
    private function getCompressionManager(): CompressionManager
    {
        return $this->compressionManager;
    }

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods(): array
    {
        return $this->getCompressionManager()->list();
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
     * Encrypter constructor.
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
     * @param JWE $jwe
     */
    public function encrypt(JWE &$jwe)
    {
        Assertion::false($jwe->isEncrypted(), 'The JWE is already encrypted.');
        Assertion::greaterThan($jwe->countRecipients(), 0, 'The JWE does not contain recipient.');
        $additional_headers = [];
        $nb_recipients = $jwe->countRecipients();
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($jwe);
        $compression_method = $this->getCompressionMethod($jwe);
        $key_management_mode = $this->getKeyManagementMode($jwe);
        $cek = $this->determineCEK($jwe, $content_encryption_algorithm, $key_management_mode, $additional_headers);

        for ($i = 0; $i < $nb_recipients; $i++) {
            $this->processRecipient($jwe, $jwe->getRecipient($i), $cek, $content_encryption_algorithm, $additional_headers);
        }

        if (!empty($additional_headers) && 1 === $jwe->countRecipients()) {
            $jwe = $jwe->withSharedProtectedHeaders(array_merge($jwe->getSharedProtectedHeaders(), $additional_headers));
        }

        $iv_size = $content_encryption_algorithm->getIVSize();
        $iv = $this->createIV($iv_size);

        $this->encryptJWE($jwe, $content_encryption_algorithm, $cek, $iv, $compression_method);
    }

    /**
     * @param JWE                           $jwe
     * @param Recipient                     $recipient
     * @param string                                              $cek
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param array                                               $additional_headers
     */
    private function processRecipient(JWE $jwe, Recipient &$recipient, $cek, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers)
    {
        if (null === $recipient->getRecipientKey()) {
            return;
        }
        $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $recipient->getHeaders());
        $key_encryption_algorithm = $this->findKeyEncryptionAlgorithm($complete_headers);
        $this->checkKeys($key_encryption_algorithm, $content_encryption_algorithm, $recipient->getRecipientKey());
        $encrypted_content_encryption_key = $this->getEncryptedKey($complete_headers, $cek, $key_encryption_algorithm, $content_encryption_algorithm, $additional_headers, $recipient->getRecipientKey());
        $recipient_headers = $recipient->getHeaders();
        if (!empty($additional_headers) && 1 !== $jwe->countRecipients()) {
            $recipient_headers = array_merge($recipient_headers, $additional_headers);
            $additional_headers = [];
        }

        $recipient = Recipient::createRecipientFromLoadedJWE($recipient_headers, $encrypted_content_encryption_key);
    }

    /**
     * @param JWE                           $jwe
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param string                                              $cek
     * @param string                                              $iv
     * @param CompressionInterface|null         $compression_method
     */
    private function encryptJWE(JWE &$jwe, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, $cek, $iv, CompressionInterface $compression_method = null)
    {
        if (!empty($jwe->getSharedProtectedHeaders())) {
            $jwe = $jwe->withEncodedSharedProtectedHeaders(Base64Url::encode(json_encode($jwe->getSharedProtectedHeaders())));
        }

        $tag = null;
        $payload = $this->preparePayload($jwe->getPayload(), $compression_method);
        $aad = null === $jwe->getAAD() ? null : Base64Url::encode($jwe->getAAD());
        $ciphertext = $content_encryption_algorithm->encryptContent($payload, $cek, $iv, $aad, $jwe->getEncodedSharedProtectedHeaders(), $tag);
        $jwe = $jwe->withCiphertext($ciphertext);
        $jwe = $jwe->withIV($iv);

        if (null !== $tag) {
            $jwe = $jwe->withTag($tag);
        }
    }

    /**
     * @param string                                      $payload
     * @param CompressionInterface|null $compression_method
     *
     * @return string
     */
    private function preparePayload($payload, CompressionInterface $compression_method = null)
    {
        $prepared = is_string($payload) ? $payload : json_encode($payload);
        Assertion::notNull($prepared, 'The payload is empty or cannot encoded into JSON.');

        if (null === $compression_method) {
            return $prepared;
        }
        $compressed_payload = $compression_method->compress($prepared);
        Assertion::string($compressed_payload, 'Compression failed.');

        return $compressed_payload;
    }

    /**
     * @param array                                               $complete_headers
     * @param string                                              $cek
     * @param KeyEncryptionAlgorithmInterface     $key_encryption_algorithm
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param JWKInterface                           $recipient_key
     * @param array                                               $additional_headers
     *
     * @return string|null
     */
    private function getEncryptedKey(array $complete_headers, $cek, KeyEncryptionAlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers, JWKInterface $recipient_key)
    {
        if ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $this->getEncryptedKeyFromKeyEncryptionAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $recipient_key, $additional_headers);
        } elseif ($key_encryption_algorithm instanceof KeyWrappingInterface) {
            return $this->getEncryptedKeyFromKeyWrappingAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $recipient_key, $additional_headers);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $this->getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm($complete_headers, $cek, $key_encryption_algorithm, $content_encryption_algorithm, $additional_headers, $recipient_key);
        }
    }

    /**
     * @param array                                                       $complete_headers
     * @param string                                                      $cek
     * @param KeyAgreementWrappingInterface $key_encryption_algorithm
     * @param ContentEncryptionAlgorithmInterface         $content_encryption_algorithm
     * @param array                                                       $additional_headers
     * @param JWKInterface                                   $recipient_key
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyAgreementAndKeyWrappingAlgorithm(array $complete_headers, $cek, KeyAgreementWrappingInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array &$additional_headers, JWKInterface $recipient_key)
    {
        $jwt_cek = $key_encryption_algorithm->wrapAgreementKey($recipient_key, $cek, $content_encryption_algorithm->getCEKSize(), $complete_headers, $additional_headers);

        return $jwt_cek;
    }

    /**
     * @param array                                                $complete_headers
     * @param string                                               $cek
     * @param KeyEncryptionInterface $key_encryption_algorithm
     * @param JWKInterface                            $recipient_key
     * @param array                                                $additional_headers
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyEncryptionAlgorithm(array $complete_headers, $cek, KeyEncryptionInterface $key_encryption_algorithm, JWKInterface $recipient_key, array &$additional_headers)
    {
        return $key_encryption_algorithm->encryptKey($recipient_key, $cek, $complete_headers, $additional_headers);
    }

    /**
     * @param array                                              $complete_headers
     * @param string                                             $cek
     * @param KeyWrappingInterface $key_encryption_algorithm
     * @param JWKInterface                          $recipient_key
     * @param array                                              $additional_headers
     *
     * @return string
     */
    private function getEncryptedKeyFromKeyWrappingAlgorithm(array $complete_headers, $cek, KeyWrappingInterface $key_encryption_algorithm, JWKInterface $recipient_key, &$additional_headers)
    {
        return $key_encryption_algorithm->wrapKey($recipient_key, $cek, $complete_headers, $additional_headers);
    }



    ////////////////////////////

    /**
     * @param KeyEncryptionAlgorithmInterface     $key_encryption_algorithm
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param JWKInterface                           $recipient_key
     */
    private function checkKeys(KeyEncryptionAlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, JWKInterface $recipient_key)
    {
        $this->checkKeyUsage($recipient_key, 'encryption');
        if ('dir' !== $key_encryption_algorithm->name()) {
            $this->checkKeyAlgorithm($recipient_key, $key_encryption_algorithm->name());
        } else {
            $this->checkKeyAlgorithm($recipient_key, $content_encryption_algorithm->name());
        }
    }

    /**
     * @param JWE                           $jwe
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param string                                              $key_management_mode
     * @param array                                               $additional_headers
     *
     * @return string
     */
    private function determineCEK(JWE $jwe, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, $key_management_mode, array &$additional_headers): string
    {
        switch ($key_management_mode) {
            case KeyEncryptionInterface::MODE_ENCRYPT:
            case KeyEncryptionInterface::MODE_WRAP:
                return $this->createCEK($content_encryption_algorithm->getCEKSize());
            case KeyEncryptionInterface::MODE_AGREEMENT:
                Assertion::eq(1, $jwe->countRecipients(), 'Unable to encrypt for multiple recipients using key agreement algorithms.');
                $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $jwe->getRecipient(0)->getHeaders());
                $algorithm = $this->findKeyEncryptionAlgorithm($complete_headers);

                return $algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $content_encryption_algorithm->name(), $jwe->getRecipient(0)->getRecipientKey(), $complete_headers, $additional_headers);
            case KeyEncryptionInterface::MODE_DIRECT:
                Assertion::eq(1, $jwe->countRecipients(), 'Unable to encrypt for multiple recipients using key agreement algorithms.');
                Assertion::eq($jwe->getRecipient(0)->getRecipientKey()->get('kty'), 'oct', 'Wrong key type.');
                Assertion::true($jwe->getRecipient(0)->getRecipientKey()->has('k'), 'The key parameter "k" is missing.');

                return Base64Url::decode($jwe->getRecipient(0)->getRecipientKey()->get('k'));
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported key management mode "%s".', $key_management_mode));
        }
    }

    /**
     * @param JWE $jwe
     *
     * @return string
     */
    private function getKeyManagementMode(JWE $jwe): string
    {
        $mode = null;
        $recipients = $jwe->getRecipients();

        foreach ($recipients as $recipient) {
            $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $recipient->getHeaders());
            Assertion::keyExists($complete_headers, 'alg', 'Parameter "alg" is missing.');

            $key_encryption_algorithm = $this->keyEncryptionAlgorithmManager->get($complete_headers['alg']);
            Assertion::isInstanceOf($key_encryption_algorithm, KeyEncryptionAlgorithmInterface::class, sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $complete_headers['alg']));

            if (null === $mode) {
                $mode = $key_encryption_algorithm->getKeyManagementMode();
            } else {
                Assertion::true($this->areKeyManagementModesCompatible($mode, $key_encryption_algorithm->getKeyManagementMode()), 'Foreign key management mode forbidden.');
            }
        }

        return $mode;
    }

    /**
     * @param JWE $jwe
     *
     * @return CompressionInterface|null
     */
    private function getCompressionMethod(JWE $jwe): ?CompressionInterface
    {
        $method = null;
        $nb_recipients = $jwe->countRecipients();

        for ($i = 0; $i < $nb_recipients; $i++) {
            $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $jwe->getRecipient($i)->getHeaders());
            if (array_key_exists('zip', $complete_headers)) {
                if (null === $method) {
                    if (0 === $i) {
                        $method = $complete_headers['zip'];
                    } else {
                        throw new \InvalidArgumentException('Inconsistent "zip" parameter.');
                    }
                } else {
                    Assertion::eq($method, $complete_headers['zip'], 'Inconsistent "zip" parameter.');
                }
            } else {
                Assertion::eq(null, $method, 'Inconsistent "zip" parameter.');
            }
        }

        if (null === $method) {
            return null;
        }

        $compression_method = $this->getCompressionManager()->get($method);
        Assertion::isInstanceOf($compression_method, CompressionInterface::class, sprintf('Compression method "%s" not supported.', $method));

        return $compression_method;
    }

    /**
     * @param JWE $jwe
     *
     * @return ContentEncryptionAlgorithmInterface
     */
    private function getContentEncryptionAlgorithm(JWE $jwe): ContentEncryptionAlgorithmInterface
    {
        $algorithm = null;

        foreach ($jwe->getRecipients() as $recipient) {
            $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $recipient->getHeaders());
            Assertion::keyExists($complete_headers, 'enc', 'Parameter "enc" is missing.');
            if (null === $algorithm) {
                $algorithm = $complete_headers['enc'];
            } else {
                Assertion::eq($algorithm, $complete_headers['enc'], 'Foreign content encryption algorithms are not allowed.');
            }
        }

        $content_encryption_algorithm = $this->contentEncryptionAlgorithmManager->get($algorithm);
        Assertion::isInstanceOf($content_encryption_algorithm, ContentEncryptionAlgorithmInterface::class, sprintf('The content encryption algorithm "%s" is not supported or not a content encryption algorithm instance.', $algorithm));

        return $content_encryption_algorithm;
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
        $supported_key_management_mode_combinations = [$enc.$enc     => true, $enc.$wrap    => true, $wrap.$enc    => true, $wrap.$wrap   => true, $agree.$agree => false, $agree.$dir   => false, $agree.$enc   => false, $agree.$wrap  => false, $dir.$agree   => false, $dir.$dir     => false, $dir.$enc     => false, $dir.$wrap    => false, $enc.$agree   => false, $enc.$dir     => false, $wrap.$agree  => false, $wrap.$dir    => false];

        if (array_key_exists($current.$new, $supported_key_management_mode_combinations)) {
            return $supported_key_management_mode_combinations[$current.$new];
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
     * @param array $complete_headers
     *
     * @return KeyEncryptionAlgorithmInterface
     */
    private function findKeyEncryptionAlgorithm(array $complete_headers): KeyEncryptionAlgorithmInterface
    {
        Assertion::keyExists($complete_headers, 'alg', 'Parameter "alg" is missing.');
        $key_encryption_algorithm = $this->keyEncryptionAlgorithmManager->get($complete_headers['alg']);
        Assertion::isInstanceOf($key_encryption_algorithm, KeyEncryptionAlgorithmInterface::class, sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $complete_headers['alg']));

        return $key_encryption_algorithm;
    }
}
