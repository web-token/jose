<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance;

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
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\Verifier;

/**
 * @BeforeMethods({"init"})
 * @Groups({"signature"})
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
    private $jwaManager;

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
     * @param array $params
     *
     * @ParamProviders({"dataSignature"})
     */
    public function benchSignature($params)
    {
        $jwsBuilder = new JWSBuilder($this->jwaManager);
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
        $verifier = new Verifier($this->jwaManager);
        $verifier->verifyWithKey($jws, $this->getPublicKey(), null, $index);
    }

    /**
     * @return JWK
     */
    abstract protected function getPrivateKey(): JWK;

    /**
     * @return JWK
     */
    abstract protected function getPublicKey(): JWK;
}
