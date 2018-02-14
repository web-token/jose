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

use Jose\Checker\SubjectChecker as Base;

class SubjectChecker extends Base
{
    /**
     * {@inheritdoc}
     */
    protected function isSubjectAllowed($subject)
    {
        return in_array($subject, ['SUB1', 'SUB2']);
    }
}
