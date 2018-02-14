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

use Jose\Algorithm\SignatureAlgorithmInterface;

trait CommonSigningMethods
{
    /**
     * @var string[]
     */
    private $signature_algorithms;

    /**
     * {@inheritdoc}
     */
    public function getSupportedSignatureAlgorithms()
    {
        return $this->signature_algorithms;
    }

    /**
     * @param string[]|\Jose\Algorithm\SignatureAlgorithmInterface[] $signature_algorithms
     */
    private function setSignatureAlgorithms($signature_algorithms)
    {
        $result = [];
        foreach ($signature_algorithms as $signature_algorithm) {
            if (is_string($signature_algorithm)) {
                $result[] = $signature_algorithm;
            } elseif ($signature_algorithm instanceof SignatureAlgorithmInterface) {
                $result[] = $signature_algorithm->getAlgorithmName();
            } else {
                throw new \InvalidArgumentException('Parameter must be a string or an instance of SignatureAlgorithmInterface');
            }
        }
        $this->signature_algorithms = $result;
    }
}
