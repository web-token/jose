<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

use Assert\Assertion;
use Base64Url\Base64Url;

final class Verifier implements VerifierInterface
{
    use Behaviour\HasKeyChecker;
    use Behaviour\HasJWAManager;
    use Behaviour\CommonSigningMethods;

    /**
     * Verifier constructor.
     *
     * @param string[]|\Jose\Algorithm\SignatureAlgorithmInterface[] $signature_algorithms
     */
    public function __construct(array $signature_algorithms)
    {
        $this->setSignatureAlgorithms($signature_algorithms);
        $this->setJWAManager(Factory\AlgorithmManagerFactory::createAlgorithmManager($signature_algorithms));
    }

    /**
     * {@inheritdoc}
     */
    public static function createVerifier(array $signature_algorithms)
    {
        $verifier = new self($signature_algorithms);

        return $verifier;
    }

    /**
     * {@inheritdoc}
     *
     * @throws \InvalidArgumentException
     */
    public function verifyWithKey(Object\JWSInterface $jws, Object\JWKInterface $jwk, $detached_payload = null, &$recipient_index = null)
    {
        $jwk_set = new Object\JWKSet();
        $jwk_set->addKey($jwk);

        $this->verifySignatures($jws, $jwk_set, $detached_payload, $recipient_index);
    }

    /**
     * {@inheritdoc}
     */
    public function verifyWithKeySet(Object\JWSInterface $jws, Object\JWKSetInterface $jwk_set, $detached_payload = null, &$recipient_index = null)
    {
        $this->verifySignatures($jws, $jwk_set, $detached_payload, $recipient_index);
    }

    /**
     * @param \Jose\Object\JWSInterface       $jws
     * @param \Jose\Object\JWKSetInterface    $jwk_set
     * @param \Jose\Object\SignatureInterface $signature
     * @param string|null                     $detached_payload
     *
     * @return bool
     */
    private function verifySignature(Object\JWSInterface $jws, Object\JWKSetInterface $jwk_set, Object\SignatureInterface $signature, $detached_payload = null)
    {
        $input = $this->getInputToVerify($jws, $signature, $detached_payload);
        foreach ($jwk_set->getKeys() as $jwk) {
            $algorithm = $this->getAlgorithm($signature);
            try {
                $this->checkKeyUsage($jwk, 'verification');
                $this->checkKeyAlgorithm($jwk, $algorithm->getAlgorithmName());
                if (true === $algorithm->verify($jwk, $input, $signature->getSignature())) {
                    return true;
                }
            } catch (\Exception $e) {
                //We do nothing, we continue with other keys
                continue;
            }
        }

        return false;
    }

    /**
     * @param \Jose\Object\JWSInterface       $jws
     * @param \Jose\Object\SignatureInterface $signature
     * @param string|null                     $detached_payload
     *
     * @return string
     */
    private function getInputToVerify(Object\JWSInterface $jws, Object\SignatureInterface $signature, $detached_payload)
    {
        $encoded_protected_headers = $signature->getEncodedProtectedHeaders();
        if (!$signature->hasProtectedHeader('b64') || true === $signature->getProtectedHeader('b64')) {
            if (null !== $jws->getEncodedPayload($signature)) {
                return sprintf('%s.%s', $encoded_protected_headers, $jws->getEncodedPayload($signature));
            }

            $payload = empty($jws->getPayload()) ? $detached_payload : $jws->getPayload();
            $payload = is_string($payload) ? $payload : json_encode($payload);

            return sprintf('%s.%s', $encoded_protected_headers, Base64Url::encode($payload));
        }

        $payload = empty($jws->getPayload()) ? $detached_payload : $jws->getPayload();
        $payload = is_string($payload) ? $payload : json_encode($payload);

        return sprintf('%s.%s', $encoded_protected_headers, $payload);
    }

    /**
     * @param \Jose\Object\JWSInterface    $jws
     * @param \Jose\Object\JWKSetInterface $jwk_set
     * @param string|null                  $detached_payload
     * @param int|null                     $recipient_index
     */
    private function verifySignatures(Object\JWSInterface $jws, Object\JWKSetInterface $jwk_set, $detached_payload = null, &$recipient_index = null)
    {
        $this->checkPayload($jws, $detached_payload);
        $this->checkJWKSet($jwk_set);
        $this->checkSignatures($jws);

        $nb_signatures = $jws->countSignatures();

        for ($i = 0; $i < $nb_signatures; $i++) {
            $signature = $jws->getSignature($i);
            $result = $this->verifySignature($jws, $jwk_set, $signature, $detached_payload);

            if (true === $result) {
                $recipient_index = $i;

                return;
            }
        }

        throw new \InvalidArgumentException('Unable to verify the JWS.');
    }

    /**
     * @param \Jose\Object\JWSInterface $jws
     */
    private function checkSignatures(Object\JWSInterface $jws)
    {
        Assertion::greaterThan($jws->countSignatures(), 0, 'The JWS does not contain any signature.');
    }

    /**
     * @param \Jose\Object\JWKSetInterface $jwk_set
     */
    private function checkJWKSet(Object\JWKSetInterface $jwk_set)
    {
        Assertion::greaterThan($jwk_set->countKeys(), 0, 'There is no key in the key set.');
    }

    /**
     * @param \Jose\Object\JWSInterface $jws
     * @param null|string               $detached_payload
     */
    private function checkPayload(Object\JWSInterface $jws, $detached_payload = null)
    {
        Assertion::false(
            null !== $detached_payload && !empty($jws->getPayload()),
            'A detached payload is set, but the JWS already has a payload.'
        );
        Assertion::true(
            !empty($jws->getPayload()) || null !== $detached_payload,
            'No payload.'
        );
    }

    /**
     * @param \Jose\Object\SignatureInterface $signature
     *
     * @return \Jose\Algorithm\SignatureAlgorithmInterface
     */
    private function getAlgorithm(Object\SignatureInterface $signature)
    {
        $complete_headers = array_merge(
            $signature->getProtectedHeaders(),
            $signature->getHeaders()
        );
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header.');

        $algorithm = $this->getJWAManager()->getAlgorithm($complete_headers['alg']);
        Assertion::isInstanceOf($algorithm, Algorithm\SignatureAlgorithmInterface::class, sprintf('The algorithm "%s" is not supported or does not implement SignatureInterface.', $complete_headers['alg']));

        return $algorithm;
    }
}
