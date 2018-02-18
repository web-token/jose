<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Stub;

use Jose\Checker\JtiChecker as Base;

class JtiChecker extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function isJtiValid($jti)
    {
        return in_array($jti, ['JTI1', 'JTI2']);
    }
}
