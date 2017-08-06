<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWS\Signature;

use Base64Url\Base64Url;
use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\None;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\SignatureAlgorithmInterface;

/**
 * @BeforeMethods({"init"})
 * @Revs(100)
 */
abstract class SignatureBench
{
    /**
     * @param JWAManager
     */
    protected $jwaManager;

    public function init()
    {
        $this->jwaManager = JWAManager::create([
            new HS256(),
            new HS384(),
            new HS512(),
            new RS256(),
            new RS384(),
            new RS512(),
            new PS256(),
            new PS384(),
            new PS512(),
            new ES256(),
            new ES384(),
            new ES512(),
            new None(),
            new EdDSA(),
        ]);
    }

    /**
     *
     */
    public function benchSignature()
    {
        $this->getAlgorithm()->sign($this->getPrivateKey(), $this->getInput());
    }

    /**
     * @param array $params
     *
     * @ParamProviders({"dataVerification"})
     */
    public function benchVerification($params)
    {
        $signature = '' === $params['signature'] ? $params['signature'] : Base64Url::decode($params['signature']);
        $this->getAlgorithm()->verify($this->getPublicKey(), $this->getInput(), $signature);
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
