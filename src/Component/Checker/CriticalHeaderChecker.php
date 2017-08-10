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

namespace Jose\Component\Checker;

final class CriticalHeaderChecker implements HeaderCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkHeader(array $protectedHeaders, array $headers, array $checkedClaims)
    {
        if (!array_key_exists('crit', $protectedHeaders)) {
            return;
        }

        if (!is_array($protectedHeaders['crit'])) {
            throw new \InvalidArgumentException('The parameter "crit" must be a list.');
        }

        $diff = array_diff($protectedHeaders['crit'], $checkedClaims);
        if (!empty($diff)) {
            throw new \InvalidArgumentException(sprintf('One or more claims are marked as critical, but they are missing or have not been checked (%s).', json_encode(array_values($diff))));
        }
    }
}
