<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Signature;

use Assert\Assertion;
use Base64Url\Base64Url;
use Jose\Component\Core\JWAManager;
use Jose\Behaviour\HasKeyChecker;
use Jose\Component\Core\JWKInterface;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\JWKSetInterface;
use Jose\Component\Signature\Object\JWS;
use Jose\Component\Signature\Object\Signature;

final class Verifier
{
    use HasKeyChecker;

    /**
     * @var JWAManager
     */
    private $signatureAlgorithmManager;

    /**
     * Signer constructor.
     *
     * @param JWAManager $signatureAlgorithmManager
     */
    public function __construct(JWAManager $signatureAlgorithmManager)
    {
        $this->signatureAlgorithmManager = $signatureAlgorithmManager;
    }

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms(): array
    {
        return $this->signatureAlgorithmManager->list();
    }

    /**
     * @param JWS          $jws
     * @param JWKInterface $jwk
     * @param null|string  $detached_payload
     * @param int|null     $signature_index
     */
    public function verifyWithKey(JWS $jws, JWKInterface $jwk, ?string $detached_payload = null, ?int &$signature_index = null)
    {
        $jwk_set = new JWKSet();
        $jwk_set->addKey($jwk);

        $this->verifySignatures($jws, $jwk_set, $detached_payload, $signature_index);
    }

    /**
     * Verify the signature of the input.
     * The input must be a valid JWS. This method is usually called after the "load" method.
     *
     * @param JWS             $jws              A JWS object.
     * @param JWKSetInterface $jwk_set          The signature will be verified using keys in the key set
     * @param null|string     $detached_payload If not null, the value must be the detached payload encoded in Base64 URL safe. If the input contains a payload, throws an exception.
     * @param null|int        $signature_index  If the JWS has been verified, an integer that represents the ID of the signature is set
     */
    public function verifyWithKeySet(JWS $jws, JWKSetInterface $jwk_set, ?string $detached_payload = null, ?int &$signature_index = null)
    {
        $this->verifySignatures($jws, $jwk_set, $detached_payload, $signature_index);
    }

    /**
     * @param JWS             $jws
     * @param JWKSetInterface $jwk_set
     * @param Signature       $signature
     * @param string|null     $detached_payload
     *
     * @return bool
     */
    private function verifySignature(JWS $jws, JWKSetInterface $jwk_set, Signature $signature, ?string $detached_payload = null): bool
    {
        $input = $this->getInputToVerify($jws, $signature, $detached_payload);
        foreach ($jwk_set->getKeys() as $jwk) {
            $algorithm = $this->getAlgorithm($signature);
            try {
                $this->checkKeyUsage($jwk, 'verification');
                $this->checkKeyAlgorithm($jwk, $algorithm->name());
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
     * @param JWS         $jws
     * @param Signature   $signature
     * @param string|null $detached_payload
     *
     * @return string
     */
    private function getInputToVerify(JWS $jws, Signature $signature, ?string $detached_payload): string
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
     * @param JWS             $jws
     * @param JWKSetInterface $jwk_set
     * @param string|null     $detached_payload
     * @param int|null        $recipient_index
     */
    private function verifySignatures(JWS $jws, JWKSetInterface $jwk_set, ?string $detached_payload = null, ?int &$recipient_index = null)
    {
        $this->checkPayload($jws, $detached_payload);
        $this->checkJWKSet($jwk_set);
        $this->checkSignatures($jws);

        $nb_signatures = $jws->countSignatures();

        for ($i = 0; $i < $nb_signatures; ++$i) {
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
    private function checkSignatures(JWS $jws)
    {
        Assertion::greaterThan($jws->countSignatures(), 0, 'The JWS does not contain any signature.');
    }

    /**
     * @param JWKSetInterface $jwk_set
     */
    private function checkJWKSet(JWKSetInterface $jwk_set)
    {
        Assertion::greaterThan($jwk_set->countKeys(), 0, 'There is no key in the key set.');
    }

    /**
     * @param JWS         $jws
     * @param null|string $detached_payload
     */
    private function checkPayload(JWS $jws, ?string $detached_payload = null)
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
    private function getAlgorithm(Signature $signature): SignatureAlgorithmInterface
    {
        $complete_headers = array_merge(
            $signature->getProtectedHeaders(),
            $signature->getHeaders()
        );
        Assertion::keyExists($complete_headers, 'alg', 'No "alg" parameter set in the header.');

        $algorithm = $this->signatureAlgorithmManager->get($complete_headers['alg']);
        Assertion::isInstanceOf($algorithm, SignatureAlgorithmInterface::class, sprintf('The algorithm "%s" is not supported or is not a signature algorithm.', $complete_headers['alg']));

        return $algorithm;
    }
}
