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
use Jose\Algorithm\SignatureAlgorithmInterface;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWS;
use Jose\Object\Signature;

final class Verifier
{
    use Behaviour\HasKeyChecker;
    use Behaviour\HasJWAManager;
    use Behaviour\CommonSigningMethods;

    /**
     * Verifier constructor.
     *
     * @param string[]|SignatureAlgorithmInterface[] $signature_algorithms
     */
    public function __construct(array $signature_algorithms)
    {
        $this->setSignatureAlgorithms($signature_algorithms);
        $this->setJWAManager(Factory\AlgorithmManagerFactory::createAlgorithmManager($signature_algorithms));
    }

    /**
     * Signer constructor.
     *
     * @param string[]|SignatureAlgorithmInterface[] $signature_algorithms
     *
     * @return Verifier
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
    public function verifyWithKey(Object\JWS $jws, Object\JWKInterface $jwk, $detached_payload = null, &$recipient_index = null)
    {
        $jwk_set = new Object\JWKSet();
        $jwk_set->addKey($jwk);

        $this->verifySignatures($jws, $jwk_set, $detached_payload, $recipient_index);
    }

    /**
     * Verify the signature of the input.
     * The input must be a valid JWS. This method is usually called after the "load" method.
     *
     * @param JWS    $jws              A JWS object.
     * @param JWKSetInterface $jwk_set          The signature will be verified using keys in the key set
     * @param null|string     $detached_payload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     * @param null|int        $signature_index  If the JWS has been verified, an integer that represents the ID of the signature is set
     */
    public function verifyWithKeySet(Object\JWS $jws, Object\JWKSetInterface $jwk_set, $detached_payload = null, &$recipient_index = null)
    {
        $this->verifySignatures($jws, $jwk_set, $detached_payload, $recipient_index);
    }

    /**
     * @param JWS       $jws
     * @param JWKSetInterface    $jwk_set
     * @param Signature $signature
     * @param string|null                     $detached_payload
     *
     * @return bool
     */
    private function verifySignature(Object\JWS $jws, Object\JWKSetInterface $jwk_set, Object\Signature $signature, $detached_payload = null)
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
     * @param JWS       $jws
     * @param Signature $signature
     * @param string|null                     $detached_payload
     *
     * @return string
     */
    private function getInputToVerify(Object\JWS $jws, Object\Signature $signature, $detached_payload)
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
     * @param JWS    $jws
     * @param JWKSetInterface $jwk_set
     * @param string|null                  $detached_payload
     * @param int|null                     $recipient_index
     */
    private function verifySignatures(Object\JWS $jws, Object\JWKSetInterface $jwk_set, $detached_payload = null, &$recipient_index = null)
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
     * @param JWS $jws
     */
    private function checkSignatures(Object\JWS $jws)
    {
        Assertion::greaterThan($jws->countSignatures(), 0, 'The JWS does not contain any signature.');
    }

    /**
     * @param JWKSetInterface $jwk_set
     */
    private function checkJWKSet(Object\JWKSetInterface $jwk_set)
    {
        Assertion::greaterThan($jwk_set->countKeys(), 0, 'There is no key in the key set.');
    }

    /**
     * @param JWS $jws
     * @param null|string               $detached_payload
     */
    private function checkPayload(Object\JWS $jws, $detached_payload = null)
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
     * @param Signature $signature
     *
     * @return SignatureAlgorithmInterface
     */
    private function getAlgorithm(Object\Signature $signature)
    {
        $complete_headers = array_merge(
            $signature->getProtectedHeaders(),
            $signature->getHeaders()
        );
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header.');

        $algorithm = $this->getJWAManager()->get($complete_headers['alg']);
        Assertion::isInstanceOf($algorithm, Algorithm\SignatureAlgorithmInterface::class, sprintf('The algorithm "%s" is not supported or does not implement Signature.', $complete_headers['alg']));

        return $algorithm;
    }
}
