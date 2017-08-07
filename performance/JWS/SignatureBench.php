<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWS;

use Base64Url\Base64Url;
use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\SignatureAlgorithmInterface;
use Jose\Component\Signature\Verifier;

/**
 * @BeforeMethods({"init"})
 * @Revs(100)
 */
abstract class SignatureBench
{
    /**
     * @var string
     */
    private $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";

    /**
     * @param JWAManager
     */
    private $signatureAlgorithmsManager;

    public function init()
    {
        $this->signatureAlgorithmsManager = JWAManager::create([
            new Algorithm\HS256(),
            new Algorithm\HS384(),
            new Algorithm\HS512(),
            new Algorithm\RS256(),
            new Algorithm\RS384(),
            new Algorithm\RS512(),
            new Algorithm\PS256(),
            new Algorithm\PS384(),
            new Algorithm\PS512(),
            new Algorithm\ES256(),
            new Algorithm\ES384(),
            new Algorithm\ES512(),
            new Algorithm\None(),
            new Algorithm\EdDSA(),
        ]);
    }

    /**
     * @param array $params
     *
     * @ParamProviders({"dataSignature"})
     */
    public function benchSignature($params)
    {
        $jwsBuilder = new JWSBuilder($this->signatureAlgorithmsManager);
        $jwsBuilder
            ->withPayload($this->payload)
            ->addSignature($this->getPrivateKey(), ['alg' => $params['algorithm']])
            ->build()
            ->toCompactJSON(0);
    }

    /**
     * @param array $params
     *
     * @ParamProviders({"dataVerification"})
     */
    public function benchVerification($params)
    {
        $jws = JWSLoader::load($params['input']);
        $verifier = new Verifier($this->signatureAlgorithmsManager);
        $verifier->verifyWithKey($jws, $this->getPublicKey(), null, $index);
    }

    public function benchSignOnly()
    {
        $this->getAlgorithm()->sign($this->getPrivateKey(), $this->getInput());
    }

    /**
     * @param array $params
     *
     * @ParamProviders({"dataVerify"})
     */
    public function benchVerifyOnly($params)
    {
        $signature = '' === $params['signature'] ? $params['signature'] : Base64Url::decode($params['signature']);
        $this->getAlgorithm()->verify($this->getPublicKey(), $this->getInput(), $signature);
    }

    /**
     * @return JWAManager
     */
    protected function getSignatureAlgorithmsManager(): JWAManager
    {
        return $this->signatureAlgorithmsManager;
    }

    /**
     * @return SignatureAlgorithmInterface
     */
    abstract protected function getAlgorithm(): SignatureAlgorithmInterface;

    /**
     * @return string
     */
    abstract protected function getInput(): string;

    /**
     * @return JWK
     */
    abstract protected function getPrivateKey(): JWK;

    /**
     * @return JWK
     */
    abstract protected function getPublicKey(): JWK;
}
