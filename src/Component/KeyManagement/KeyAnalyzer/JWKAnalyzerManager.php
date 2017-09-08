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

namespace Jose\Component\KeyManagement\KeyAnalyzer;

use Jose\Component\Core\JWK;

final class JWKAnalyzerManager
{
    /**
     * @var JWKAnalyzerInterface[]
     */
    private $analyzers = [];

    /**
     * @param JWKAnalyzerInterface $analyzer
     */
    public function add(JWKAnalyzerInterface $analyzer)
    {
        $this->analyzers[] = $analyzer;
    }

    /**
     * @param JWK $jwk
     *
     * @return string[]
     */
    public function analyze(JWK $jwk): array
    {
        $messages = [];
        foreach ($this->analyzers as $analyzer) {
            $analyzer->analyze($jwk, $messages);
        }

        return $messages;
    }
}