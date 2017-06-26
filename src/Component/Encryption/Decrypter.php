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

use Base64Url\Base64Url;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Component\Core\JWAInterface;
use Jose\Component\Core\JWAManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\DirectEncryptionInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyAgreementWrappingInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyEncryptionInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryption\KeyWrappingInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Component\Core\KeyChecker;
use Jose\Component\Encryption\Compression\CompressionManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\JWKSetInterface;

final class Decrypter
{
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
     * Decrypter constructor.
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
     * @param JWE      $jwe             A JWE object to decrypt
     * @param JWK      $jwk             The key used to decrypt the input
     * @param null|int $recipient_index If the JWE has been decrypted, an integer that represents the ID of the recipient is set
     */
    public function decryptUsingKey(JWE &$jwe, JWK $jwk, ?int &$recipient_index = null)
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        $this->decryptUsingKeySet($jwe, $jwk_set, $recipient_index);
    }

    /**
     * @param JWE             $jwe             A JWE object to decrypt
     * @param JWKSetInterface $jwk_set         The key set used to decrypt the input
     * @param null|int        $recipient_index If the JWE has been decrypted, an integer that represents the ID of the recipient is set
     */
    public function decryptUsingKeySet(JWE &$jwe, JWKSetInterface $jwk_set, &$recipient_index = null)
    {
        $this->checkJWKSet($jwk_set);
        $this->checkPayload($jwe);
        $this->checkRecipients($jwe);

        $nb_recipients = $jwe->countRecipients();

        for ($i = 0; $i < $nb_recipients; ++$i) {
            if (is_int($result = $this->decryptRecipientKey($jwe, $jwk_set, $i))) {
                $recipient_index = $result;

                return;
            }
        }

        throw new \InvalidArgumentException('Unable to decrypt the JWE.');
    }

    /**
     * @param JWE             $jwe
     * @param JWKSetInterface $jwk_set
     * @param int             $i
     *
     * @return int|null
     */
    private function decryptRecipientKey(JWE &$jwe, JWKSetInterface $jwk_set, $i): ?int
    {
        $recipient = $jwe->getRecipient($i);
        $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $recipient->getHeaders());
        $this->checkCompleteHeader($complete_headers);

        $key_encryption_algorithm = $this->getKeyEncryptionAlgorithm($complete_headers);
        $content_encryption_algorithm = $this->getContentEncryptionAlgorithm($complete_headers);

        foreach ($jwk_set as $jwk) {
            try {
                KeyChecker::checkKeyUsage($jwk, 'decryption');
                if ('dir' !== $key_encryption_algorithm->name()) {
                    KeyChecker::checkKeyAlgorithm($jwk, $key_encryption_algorithm->name());
                } else {
                    KeyChecker::checkKeyAlgorithm($jwk, $content_encryption_algorithm->name());
                }
                $cek = $this->decryptCEK($key_encryption_algorithm, $content_encryption_algorithm, $jwk, $recipient, $complete_headers);
                if (null !== $cek) {
                    if (true === $this->decryptPayload($jwe, $cek, $content_encryption_algorithm, $complete_headers)) {
                        return $i;
                    }
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
     * @param JWKSetInterface $jwk_set
     */
    private function checkJWKSet(JWKSetInterface $jwk_set)
    {
        if (0 === $jwk_set->count()) {
            throw new \InvalidArgumentException('No key in the key set.');
        }
    }

    /**
     * @param JWAInterface                        $key_encryption_algorithm
     * @param ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param JWK                                 $key
     * @param Recipient                           $recipient
     * @param array                               $complete_headers
     *
     * @return null|string
     */
    private function decryptCEK(JWAInterface $key_encryption_algorithm, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, JWK $key, Recipient $recipient, array $complete_headers): ?string
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
     * @return bool
     */
    private function decryptPayload(JWE &$jwe, $cek, ContentEncryptionAlgorithmInterface $content_encryption_algorithm, array $complete_headers): bool
    {
        $payload = $content_encryption_algorithm->decryptContent($jwe->getCiphertext(), $cek, $jwe->getIV(), null === $jwe->getAAD() ? null : Base64Url::encode($jwe->getAAD()), $jwe->getEncodedSharedProtectedHeaders(), $jwe->getTag());
        if (null === $payload) {
            return false;
        }

        $this->decompressIfNeeded($payload, $complete_headers);
        $decoded = json_decode($payload, true);
        $jwe = $jwe->withPayload(null === $decoded ? $payload : $decoded);

        return true;
    }

    /**
     * @param string $payload
     * @param array  $complete_headers
     */
    private function decompressIfNeeded(&$payload, array $complete_headers)
    {
        if (array_key_exists('zip', $complete_headers)) {
            $compression_method = $this->getCompressionManager()->get($complete_headers['zip']);
            $payload = $compression_method->uncompress($payload);
            if (!is_string($payload)) {
                throw new \InvalidArgumentException('Decompression failed');
            }
        }
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
    private function getKeyEncryptionAlgorithm(array $complete_headers)
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
    private function getContentEncryptionAlgorithm(array $complete_headers)
    {
        $content_encryption_algorithm = $this->contentEncryptionAlgorithmManager->get($complete_headers['enc']);
        if (!$content_encryption_algorithm instanceof ContentEncryptionAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The key encryption algorithm "%s" is not supported or does not implement ContentEncryptionInterface.', $complete_headers['enc']));
        }

        return $content_encryption_algorithm;
    }
}
