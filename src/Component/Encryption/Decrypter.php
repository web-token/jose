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
use Jose\Component\Core\AlgorithmInterface;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\KeyChecker;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\DirectEncryptionInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Compression\CompressionMethodManager;

final class Decrypter
{
    /**
     * @var AlgorithmManager
     */
    private $keyEncryptionAlgorithmManager;

    /**
     * @var AlgorithmManager
     */
    private $contentEncryptionAlgorithmManager;

    /**
     * @var CompressionMethodManager
     */
    private $compressionManager;

    /**
     * @return string[]
     */
    public function getSupportedCompressionMethods(): array
    {
        return $this->compressionManager->list();
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
     * Decrypter constructor.
     *
     * @param AlgorithmManager         $keyEncryptionAlgorithmManager
     * @param AlgorithmManager         $contentEncryptionAlgorithmManager
     * @param CompressionMethodManager $compressionManager
     */
    public function __construct(AlgorithmManager $keyEncryptionAlgorithmManager, AlgorithmManager $contentEncryptionAlgorithmManager, CompressionMethodManager $compressionManager)
    {
        $this->keyEncryptionAlgorithmManager = $keyEncryptionAlgorithmManager;
        $this->contentEncryptionAlgorithmManager = $contentEncryptionAlgorithmManager;
        $this->compressionManager = $compressionManager;
    }

    /**
     * @param JWE      $jwe            A JWE object to decrypt
     * @param JWK      $jwk            The key used to decrypt the input
     * @param null|int $recipientIndex If the JWE has been decrypted, an integer that represents the ID of the recipient is set
     *
     * @return JWE
     */
    public function decryptUsingKey(JWE $jwe, JWK $jwk, ?int &$recipientIndex = null): JWE
    {
        $jwkset = JWKSet::createFromKeys([$jwk]);

        return $this->decryptUsingKeySet($jwe, $jwkset, $recipientIndex);
    }

    /**
     * @param JWE      $jwe            A JWE object to decrypt
     * @param JWKSet   $jwkset         The key set used to decrypt the input
     * @param null|int $recipientIndex If the JWE has been decrypted, an integer that represents the ID of the recipient is set
     *
     * @return JWE
     */
    public function decryptUsingKeySet(JWE $jwe, JWKSet $jwkset, ?int &$recipientIndex = null): JWE
    {
        $this->checkJWKSet($jwkset);
        $this->checkPayload($jwe);
        $this->checkRecipients($jwe);

        $nb_recipients = $jwe->countRecipients();

        for ($i = 0; $i < $nb_recipients; ++$i) {
            $plaintext = $this->decryptRecipientKey($jwe, $jwkset, $i);
            if (null !== $plaintext) {
                $recipientIndex = $i;

                return $jwe->withPayload($plaintext);
            }
        }

        throw new \InvalidArgumentException('Unable to decrypt the JWE.');
    }

    /**
     * @param JWE    $jwe
     * @param JWKSet $jwkset
     * @param int    $i
     *
     * @return string|null
     */
    private function decryptRecipientKey(JWE $jwe, JWKSet $jwkset, int $i): ?string
    {
        $recipient = $jwe->getRecipient($i);
        $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $recipient->getHeaders());
        $this->checkCompleteHeader($complete_headers);

        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_headers);
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($complete_headers);

        foreach ($jwkset as $jwk) {
            try {
                KeyChecker::checkKeyUsage($jwk, 'decryption');
                if ('dir' !== $key_encryption_algorithm->name()) {
                    KeyChecker::checkKeyAlgorithm($jwk, $key_encryption_algorithm->name());
                } else {
                    KeyChecker::checkKeyAlgorithm($jwk, $content_encryption_algorithm->name());
                }
                $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $jwk, $recipient, $complete_headers);
                if (null !== $cek) {
                    return $this->decryptPayload($jwe, $cek, $content_encryption_algorithm, $complete_headers);
                }
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
                continue;
            }
        }

        return null;
    }

    /**
     * @param JWE $jwe
     */
    private function checkRecipients(JWE $jwe)
    {
        if (0 === $jwe->countRecipients()) {
            throw new \InvalidArgumentException('The JWE does not contain any recipient.');
        }
    }

    /**
     * @param JWE $jwe
     */
    private function checkPayload(JWE $jwe)
    {
        if (null !== $jwe->getPayload()) {
            throw new \InvalidArgumentException('The JWE is already decrypted.');
        }
    }

    /**
     * @param JWKSet $jwkset
     */
    private function checkJWKSet(JWKSet $jwkset)
    {
        if (0 === $jwkset->count()) {
            throw new \InvalidArgumentException('No key in the key set.');
        }
    }

    /**
     * @param AlgorithmInterface                  $key_encryption_algorithm
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param JWK                                 $key
     * @param Recipient                           $recipient
     * @param array                               $complete_headers
     *
     * @return null|string
     */
    private function decryptCEK(AlgorithmInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, JWK $key, Recipient $recipient, array $complete_headers): ?string
    {
        if ($key_encryption_algorithm instanceof DirectEncryptionInterface) {
            return $key_encryption_algorithm->getCEK($key);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementInterface) {
            return $key_encryption_algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $content_encryption_algorithm->name(), $key, $complete_headers);
        } elseif ($key_encryption_algorithm instanceof KeyAgreementWrappingInterface) {
            return $key_encryption_algorithm->unwrapAgreementKey($key, $recipient->getEncryptedKey(), $content_encryption_algorithm->getCEKSize(), $complete_headers);
        } elseif ($key_encryption_algorithm instanceof KeyEncryptionInterface) {
            return $key_encryption_algorithm->decryptKey($key, $recipient->getEncryptedKey(), $complete_headers);
        } elseif ($key_encryption_algorithm instanceof KeyWrappingInterface) {
            return $key_encryption_algorithm->unwrapKey($key, $recipient->getEncryptedKey(), $complete_headers);
        } else {
            throw new \InvalidArgumentException('Unsupported CEK generation');
        }
    }

    /**
     * @param JWE                                 $jwe
     * @param string                              $cek
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param array                               $complete_headers
     *
     * @return string
     */
    private function decryptPayload(JWE $jwe, string $cek, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array $complete_headers): string
    {
        $payload = $content_encryption_algorithm->decryptContent($jwe->getCiphertext(), $cek, $jwe->getIV(), null === $jwe->getAAD() ? null : Base64Url::encode($jwe->getAAD()), $jwe->getEncodedSharedProtectedHeaders(), $jwe->getTag());
        if (null === $payload) {
            throw new \RuntimeException('Unable to decrypt the JWE.');
        }

        return $this->decompressIfNeeded($payload, $complete_headers);
    }

    /**
     * @param string $payload
     * @param array  $complete_headers
     *
     * @return string
     */
    private function decompressIfNeeded(string $payload, array $complete_headers): string
    {
        if (array_key_exists('zip', $complete_headers)) {
            $compression_method = $this->compressionManager->get($complete_headers['zip']);
            $payload = $compression_method->uncompress($payload);
            if (!is_string($payload)) {
                throw new \InvalidArgumentException('Decompression failed');
            }
        }

        return $payload;
    }

    /**
     * @param array $complete_headers
     *
     * @throws \InvalidArgumentException
     */
    private function checkCompleteHeader(array $complete_headers)
    {
        foreach (['enc', 'alg'] as $key) {
            if (!array_key_exists($key, $complete_headers)) {
                throw new \InvalidArgumentException(sprintf("Parameters '%s' is missing.", $key));
            }
        }
    }

    /**
     * @param array $complete_headers
     *
     * @return KeyEncryptionAlgorithmInterface
     */
    private function getKeyEncryptionAlgorithm(array $complete_headers): KeyEncryptionAlgorithmInterface
    {
        $key_encryption_algorithm = $this->keyEncryptionAlgorithmManager->get($complete_headers['alg']);
        if (!$key_encryption_algorithm instanceof KeyEncryptionAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The key encryption algorithm "%s" is not supported or does not implement KeyEncryptionAlgorithmInterface.', $complete_headers['alg']));
        }

        return $key_encryption_algorithm;
    }

    /**
     * @param array $complete_headers
     *
     * @return ContentEncryptionAlgorithmInterface
     */
    private function getContentEncryptionAlgorithm(array $complete_headers): ContentEncryptionAlgorithmInterface
    {
        $content_encryption_algorithm = $this->contentEncryptionAlgorithmManager->get($complete_headers['enc']);
        if (!$content_encryption_algorithm instanceof ContentEncryptionAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The key encryption algorithm "%s" is not supported or does not implement ContentEncryptionInterface.', $complete_headers['enc']));
        }

        return $content_encryption_algorithm;
    }
}
