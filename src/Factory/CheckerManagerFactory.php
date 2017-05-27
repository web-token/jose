<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Factory;

use Assert\Assertion;
use Jose\Checker\CheckerManager;
use Jose\Checker\ClaimCheckerInterface;
use Jose\Checker\HeaderCheckerInterface;

final class CheckerManagerFactory
{
    /**
     * @param string[]|ClaimCheckerInterface[]  $claims
     * @param string[]|HeaderCheckerInterface[] $headers
     *
     * @return CheckerManager
     */
    public static function createClaimCheckerManager(array $claims = ['exp', 'iat', 'nbf'], array $headers = ['crit']): CheckerManager
    {
        $checker_manager = new CheckerManager();

        self::populateClaimCheckers($checker_manager, $claims);
        self::populateHeaderCheckers($checker_manager, $headers);

        return $checker_manager;
    }

    /**
     * @param CheckerManager $checker_manager
     * @param array                                 $claims
     */
    private static function populateClaimCheckers(CheckerManager $checker_manager, array $claims)
    {
        foreach ($claims as $claim) {
            if ($claim instanceof ClaimCheckerInterface) {
                $checker_manager->addClaimChecker($claim);
            } else {
                Assertion::string($claim, 'Bad argument: must be a list with either claim names (string) or instances of ClaimCheckerInterface.');
                $class = self::getClaimClass($claim);
                $checker_manager->addClaimChecker(new $class());
            }
        }
    }

    /**
     * @param CheckerManager $checker_manager
     * @param array                                 $headers
     */
    private static function populateHeaderCheckers(CheckerManager $checker_manager, array $headers)
    {
        foreach ($headers as $claim) {
            if ($claim instanceof HeaderCheckerInterface) {
                $checker_manager->addHeaderChecker($claim);
            } else {
                Assertion::string($claim, 'Bad argument: must be a list with either header names (string) or instances of HeaderCheckerInterface.');
                $class = self::getHeaderClass($claim);
                $checker_manager->addHeaderChecker(new $class());
            }
        }
    }

    /**
     * @param string $claim
     *
     * @return bool
     */
    private static function isClaimSupported(string $claim): bool
    {
        return array_key_exists($claim, self::getSupportedClaims());
    }

    /**
     * @param string $header
     *
     * @return bool
     */
    private static function isHeaderSupported(string $header): bool
    {
        return array_key_exists($header, self::getSupportedHeaders());
    }

    /**
     * @param string $claim
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getClaimClass(string $claim): string
    {
        Assertion::true(self::isClaimSupported($claim), sprintf('Claim "%s" is not supported. Please add an instance of ClaimCheckerInterface directly.', $claim));

        return self::getSupportedClaims()[$claim];
    }

    /**
     * @param string $header
     *
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private static function getHeaderClass(string $header): string
    {
        Assertion::true(self::isHeaderSupported($header), sprintf('Header "%s" is not supported. Please add an instance of HeaderCheckerInterface directly.', $header));

        return self::getSupportedHeaders()[$header];
    }

    /**
     * @return array
     */
    private static function getSupportedClaims(): array
    {
        return [
            'aud' => '\Jose\Checker\AudienceChecker',
            'exp' => '\Jose\Checker\ExpirationTimeChecker',
            'iat' => '\Jose\Checker\IssuedAtChecker',
            'nbf' => '\Jose\Checker\NotBeforeChecker',
        ];
    }

    /**
     * @return array
     */
    private static function getSupportedHeaders(): array
    {
        return [
            'crit' => '\Jose\Checker\CriticalHeaderChecker',
        ];
    }
}
