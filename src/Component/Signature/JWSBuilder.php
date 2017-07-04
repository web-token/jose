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

namespace Jose\Component\Signature;

use Base64Url\Base64Url;
use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\KeyChecker;

final class JWSBuilder
{
    /**
     * @var mixed
     */
    private $payload;

    /**
     * @var bool
     */
    private $isPayloadDetached;

    /**
     * @var array
     */
    private $signatures = [];

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
     * @param mixed $payload
     * @param bool  $isPayloadDetached
     *
     * @return JWSBuilder
     */
    public function withPayload($payload, bool $isPayloadDetached = false): JWSBuilder
    {
        $clone = clone $this;
        $clone->payload = $payload;
        $clone->isPayloadDetached = $isPayloadDetached;

        return $clone;
    }

    /**
     * @param JWK   $signatureKey
     * @param array $protectedHeaders
     * @param array $headers
     *
     * @return JWSBuilder
     */
    public function addSignature(JWK $signatureKey, array $protectedHeaders, array $headers = []): JWSBuilder
    {
        KeyChecker::checkKeyUsage($signatureKey, 'signature');
        $algorithm = $this->findSignatureAlgorithm($signatureKey, $protectedHeaders, $headers);
        KeyChecker::checkKeyAlgorithm($signatureKey, $algorithm->name());
        $clone = clone $this;
        $clone->signatures[] = [
            'signature_algorithm' => $algorithm,
            'signature_key' => $signatureKey,
            'protected_headers' => $protectedHeaders,
            'headers' => $headers,
        ];

        return $clone;
    }

    /**
     * @return JWS
     */
    public function build(): JWS
    {
        $jws = new JWS();
        $jws = $jws->withPayload($this->payload);
        if ($this->isPayloadDetached) {
            $jws = $jws->withDetachedPayload();
        }
        foreach ($this->signatures as $signature) {
            /** @var SignatureAlgorithmInterface $signatureAlgorithm */
            $signatureAlgorithm = $signature['signature_algorithm'];
            /** @var JWK $signatureKey */
            $signatureKey = $signature['signature_key'];
            /** @var array $protectedHeaders */
            $protectedHeaders = $signature['protected_headers'];
            /** @var array $headers */
            $headers = $signature['headers'];
            $encodedProtectedHeaders = empty($protectedHeaders) ? null : Base64Url::encode(json_encode($protectedHeaders));
            $input = $this->getInputToSign($protectedHeaders, $encodedProtectedHeaders);

            $s = $signatureAlgorithm->sign($signatureKey, $input);
            $jws = $jws->addSignatureFromLoadedData($s, $encodedProtectedHeaders, $headers);
        }

        return $jws;
    }

    /**
     * @param array  $protectedHeaders
     * @param string $encodedProtectedHeaders
     *
     * @return string
     */
    private function getInputToSign(array $protectedHeaders, ?string $encodedProtectedHeaders): string
    {
        $this->checkB64AndCriticalHeader($protectedHeaders);
        if (!array_key_exists('b64', $protectedHeaders) || (array_key_exists('b64', $protectedHeaders) && true === $protectedHeaders['b64'])) {
            $encodedPayload = Base64Url::encode(is_string($this->payload) ? $this->payload : json_encode($this->payload));

            return sprintf('%s.%s', $encodedProtectedHeaders, $encodedPayload);
        }

        return sprintf('%s.%s', $encodedProtectedHeaders, $this->payload);
    }

    /**
     * @param array $protectedHeaders
     */
    private function checkB64AndCriticalHeader(array $protectedHeaders)
    {
        if (!array_key_exists('b64', $protectedHeaders)) {
            return;
        }
        if (!array_key_exists('crit', $protectedHeaders)) {
            throw new \LogicException('The protected header parameter "crit" is mandatory when protected header parameter "b64" is set.');
        }
        if (!is_array($protectedHeaders['crit'])) {
            throw new \LogicException('The protected header parameter "crit" must be an array.');
        }
        if (!in_array('b64', $protectedHeaders['crit'])) {
            throw new \LogicException('The protected header parameter "crit" must contain "b64" when protected header parameter "b64" is set.');
        }
    }

    /**
     * @param array $protectedHeader
     * @param array $headers
     * @param JWK   $key
     *
     * @return SignatureAlgorithmInterface
     */
    private function findSignatureAlgorithm(JWK $key, array $protectedHeader, array $headers): SignatureAlgorithmInterface
    {
        $completeHeader = array_merge($headers, $protectedHeader);
        if (!array_key_exists('alg', $completeHeader)) {
            throw new \InvalidArgumentException('No "alg" parameter set in the header.');
        }
        if ($key->has('alg') && $key->get('alg') !== $completeHeader['alg']) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not allowed with this key.', $completeHeader['alg']));
        }

        $signatureAlgorithm = $this->signatureAlgorithmManager->get($completeHeader['alg']);
        if (!$signatureAlgorithm instanceof SignatureAlgorithmInterface) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported.', $completeHeader['alg']));
        }

        return $signatureAlgorithm;
    }
}
