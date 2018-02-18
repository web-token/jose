<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Behaviour;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Algorithm;
use Jose\Compression;
use Jose\Object;

trait EncrypterTrait
{
    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $usage
     *
     * @throws \InvalidArgumentException
     *
     * @return bool
     */
    abstract protected function checkKeyUsage(Object\JWKInterface $key, $usage);

    /**
     * @param \Jose\Object\JWKInterface $key
     * @param string                    $algorithm
     */
    abstract protected function checkKeyAlgorithm(Object\JWKInterface $key, $algorithm);

    /**
     * @return \Jose\Algorithm\JWAManagerInterface
     */
    abstract protected function getJWAManager();

    /**
     * @return \Jose\Compression\CompressionManagerInterface
     */
    abstract protected function getCompressionManager();

    /**
     * @param \Jose\Algorithm\KeyEncryptionAlgorithmInterface     $key_encryption_algorithm
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param \Jose\Object\JWKInterface                           $recipient_key
     */
    private function checkKeys(Algorithm\KeyEncryptionAlgorithmInterface $key_encryption_algorithm, Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm, Object\JWKInterface $recipient_key)
    {
        $this->checkKeyUsage($recipient_key, 'encryption');
        if ('dir' !== $key_encryption_algorithm->getAlgorithmName()) {
            $this->checkKeyAlgorithm($recipient_key, $key_encryption_algorithm->getAlgorithmName());
        } else {
            $this->checkKeyAlgorithm($recipient_key, $content_encryption_algorithm->getAlgorithmName());
        }
    }

    /**
     * @param \Jose\Object\JWEInterface                           $jwe
     * @param \Jose\Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm
     * @param string                                              $key_management_mode
     * @param array                                               $additional_headers
     *
     * @return string
     */
    private function determineCEK(Object\JWEInterface $jwe, Algorithm\ContentEncryptionAlgorithmInterface $content_encryption_algorithm, $key_management_mode, array &$additional_headers)
    {
        switch ($key_management_mode) {
            case Algorithm\KeyEncryption\KeyEncryptionInterface::MODE_ENCRYPT:
            case Algorithm\KeyEncryption\KeyEncryptionInterface::MODE_WRAP:
                return $this->createCEK($content_encryption_algorithm->getCEKSize());
            case Algorithm\KeyEncryption\KeyEncryptionInterface::MODE_AGREEMENT:
                Assertion::eq(1, $jwe->countRecipients(), 'Unable to encrypt for multiple recipients using key agreement algorithms.');
                $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $jwe->getRecipient(0)->getHeaders());
                $algorithm = $this->findKeyEncryptionAlgorithm($complete_headers);

                return $algorithm->getAgreementKey($content_encryption_algorithm->getCEKSize(), $content_encryption_algorithm->getAlgorithmName(), $jwe->getRecipient(0)->getRecipientKey(), $complete_headers, $additional_headers);
            case Algorithm\KeyEncryption\KeyEncryptionInterface::MODE_DIRECT:
                Assertion::eq(1, $jwe->countRecipients(), 'Unable to encrypt for multiple recipients using key agreement algorithms.');
                Assertion::eq($jwe->getRecipient(0)->getRecipientKey()->get('kty'), 'oct', 'Wrong key type.');
                Assertion::true($jwe->getRecipient(0)->getRecipientKey()->has('k'), 'The key parameter "k" is missing.');

                return Base64Url::decode($jwe->getRecipient(0)->getRecipientKey()->get('k'));
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported key management mode "%s".', $key_management_mode));
        }
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     *
     * @return string
     */
    private function getKeyManagementMode(Object\JWEInterface $jwe)
    {
        $mode = null;
        $recipients = $jwe->getRecipients();

        foreach ($recipients as $recipient) {
            $complete_headers = array_merge($jwe->getSharedProtectedHeaders(), $jwe->getSharedHeaders(), $recipient->getHeaders());
            Assertion::keyExists($complete_headers, 'alg', 'Parameter "alg" is missing.');

            $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
            Assertion::isInstanceOf($key_encryption_algorithm, Algorithm\KeyEncryptionAlgorithmInterface::class, sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $complete_headers['alg']));

            if (null === $mode) {
                $mode = $key_encryption_algorithm->getKeyManagementMode();
            } else {
                Assertion::true($this->areKeyManagementModesCompatible($mode, $key_encryption_algorithm->getKeyManagementMode()), 'Foreign key management mode forbidden.');
            }
        }

        return $mode;
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     *
     * @return \Jose\Compression\CompressionInterface|null
     */
    private function getCompressionMethod(Object\JWEInterface $jwe)
    {
        $method = null;
        $nb_recipients = $jwe->countRecipients();

        for ($i = 0; $i < $nb_recipients; ++$i) {
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
            return;
        }

        $compression_method = $this->getCompressionManager()->getCompressionAlgorithm($method);
        Assertion::isInstanceOf($compression_method, Compression\CompressionInterface::class, sprintf('Compression method "%s" not supported.', $method));

        return $compression_method;
    }

    /**
     * @param \Jose\Object\JWEInterface $jwe
     *
     * @return \Jose\Algorithm\ContentEncryptionAlgorithmInterface
     */
    private function getContentEncryptionAlgorithm(Object\JWEInterface $jwe)
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

        $content_encryption_algorithm = $this->getJWAManager()->getAlgorithm($algorithm);
        Assertion::isInstanceOf($content_encryption_algorithm, Algorithm\ContentEncryptionAlgorithmInterface::class, sprintf('The content encryption algorithm "%s" is not supported or not a content encryption algorithm instance.', $algorithm));

        return $content_encryption_algorithm;
    }

    /**
     * @param string $current
     * @param string $new
     *
     * @return bool
     */
    private function areKeyManagementModesCompatible($current, $new)
    {
        $agree = Algorithm\KeyEncryptionAlgorithmInterface::MODE_AGREEMENT;
        $dir = Algorithm\KeyEncryptionAlgorithmInterface::MODE_DIRECT;
        $enc = Algorithm\KeyEncryptionAlgorithmInterface::MODE_ENCRYPT;
        $wrap = Algorithm\KeyEncryptionAlgorithmInterface::MODE_WRAP;
        $supported_key_management_mode_combinations = [$enc.$enc => true, $enc.$wrap => true, $wrap.$enc => true, $wrap.$wrap => true, $agree.$agree => false, $agree.$dir => false, $agree.$enc => false, $agree.$wrap => false, $dir.$agree => false, $dir.$dir => false, $dir.$enc => false, $dir.$wrap => false, $enc.$agree => false, $enc.$dir => false, $wrap.$agree => false, $wrap.$dir => false];

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
    private function createCEK($size)
    {
        return random_bytes($size / 8);
    }

    /**
     * @param int $size
     *
     * @return string
     */
    private function createIV($size)
    {
        return random_bytes($size / 8);
    }

    /**
     * @param array $complete_headers
     *
     * @return \Jose\Algorithm\KeyEncryptionAlgorithmInterface
     */
    private function findKeyEncryptionAlgorithm(array $complete_headers)
    {
        Assertion::keyExists($complete_headers, 'alg', 'Parameter "alg" is missing.');
        $key_encryption_algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
        Assertion::isInstanceOf($key_encryption_algorithm, Algorithm\KeyEncryptionAlgorithmInterface::class, sprintf('The key encryption algorithm "%s" is not supported or not a key encryption algorithm instance.', $complete_headers['alg']));

        return $key_encryption_algorithm;
    }
}
