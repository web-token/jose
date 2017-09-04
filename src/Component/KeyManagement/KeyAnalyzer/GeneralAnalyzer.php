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

final class GeneralAnalyzer implements JWKAnalyzerInterface
{
    /**
     * {@inheritdoc}
     */
    public function analyze(JWK $jwk, array &$messages)
    {
        foreach (['alg', 'use', 'kid'] as $key) {
            if (!$jwk->has($key)) {
                $messages[] = sprintf('The parameter "%s" should be added.', $key);
            }
        }
    }
}
