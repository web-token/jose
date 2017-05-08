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
use Jose\Object\JWKInterface;
use Jose\Object\JWS;
use Jose\Object\Signature;

final class Signer
{
    use Behaviour\HasKeyChecker;
    use Behaviour\HasJWAManager;
    use Behaviour\CommonSigningMethods;

    /**
     * Signer constructor.
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
     * @return Signer
     */
    public static function createSigner(array $signature_algorithms): Signer
    {
        $signer = new self($signature_algorithms);

        return $signer;
    }

    /**
     * @param JWS $jws
     */
    public function sign(JWS &$jws)
    {
        $nb_signatures = $jws->countSignatures();

        for ($i = 0; $i < $nb_signatures; $i++) {
            $this->computeSignature($jws, $jws->getSignature($i));
        }
    }

    /**
     * @param JWS       $jws
     * @param Signature $signature
     */
    private function computeSignature(JWS $jws, Signature &$signature)
    {
        if (null === $signature->getSignatureKey()) {
            return;
        }
        $this->checkKeyUsage($signature->getSignatureKey(), 'signature');

        $signature_algorithm = $this->getSignatureAlgorithm($signature->getAllHeaders(), $signature->getSignatureKey());

        $input = $this->getInputToSign($jws, $signature);

        $value = $signature_algorithm->sign(
            $signature->getSignatureKey(),
            $input
        );

        $signature = Object\Signature::createSignatureFromLoadedData(
            $value,
            $signature->getEncodedProtectedHeaders(),
            $signature->getHeaders()
        );
    }

    /**
     * @param JWS       $jws
     * @param Signature $signature
     *
     * @return string
     */
    private function getInputToSign(JWS $jws, Signature $signature): string
    {
        $this->checkB64HeaderAndCrit($signature);
        $encoded_protected_headers = $signature->getEncodedProtectedHeaders();
        $payload = $jws->getPayload();
        if (!$signature->hasProtectedHeader('b64') || true === $signature->getProtectedHeader('b64')) {
            $encoded_payload = Base64Url::encode(is_string($payload) ? $payload : json_encode($payload));

            return sprintf('%s.%s', $encoded_protected_headers, $encoded_payload);
        }

        return sprintf('%s.%s', $encoded_protected_headers, $payload);
    }

    /**
     * @param Signature $signature
     *
     * @throws \InvalidArgumentException
     */
    private function checkB64HeaderAndCrit(Signature $signature)
    {
        if (!$signature->hasProtectedHeader('b64')) {
            return;
        }

        Assertion::true($signature->hasProtectedHeader('crit'), 'The protected header parameter "crit" is mandatory when protected header parameter "b64" is set.');
        Assertion::isArray($signature->getProtectedHeader('crit'), 'The protected header parameter "crit" must be an array.');
        Assertion::inArray('b64', $signature->getProtectedHeader('crit'), 'The protected header parameter "crit" must contain "b64" when protected header parameter "b64" is set.');
    }

    /**
     * @param array                     $complete_header The complete header
     * @param JWKInterface $key
     *
     * @return SignatureAlgorithmInterface
     */
    private function getSignatureAlgorithm(array $complete_header, JWKInterface $key): SignatureAlgorithmInterface
    {
        Assertion::keyExists($complete_header, 'alg', 'No "alg" parameter set in the header.');

        Assertion::false(
            $key->has('alg') && $key->get('alg') !== $complete_header['alg'],
            sprintf('The algorithm "%s" is not allowed with this key.', $complete_header['alg'])
        );

        $signature_algorithm = $this->getJWAManager()->get($complete_header['alg']);
        Assertion::isInstanceOf($signature_algorithm, SignatureAlgorithmInterface::class, sprintf('The algorithm "%s" is not supported.', $complete_header['alg']));

        return $signature_algorithm;
    }
}
