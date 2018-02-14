<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose;

/**
 * Signer Interface.
 */
interface SignerInterface
{
    /**
     * Signer constructor.
     *
     * @param string[]|\Jose\Algorithm\SignatureAlgorithmInterface[] $signature_algorithms
     *
     * @return \Jose\SignerInterface
     */
    public static function createSigner(array $signature_algorithms);

    /**
     * @return string[]
     */
    public function getSupportedSignatureAlgorithms();

    /**
     * @param \Jose\Object\JWSInterface $jws
     */
    public function sign(Object\JWSInterface &$jws);
}
