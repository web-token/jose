<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Checker;

/**
 * Interface HeaderCheckerInterface.
 */
interface HeaderCheckerInterface
{
    /**
     * @param array $protected_headers
     * @param array $headers
     * @param array $checked_claims
     */
    public function checkHeader(array $protected_headers, array $headers, array $checked_claims);
}
