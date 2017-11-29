<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Unit\Checker;

use Assert\InvalidArgumentException;
use Jose\Checker\ExpirationTimeChecker;
use Jose\Factory\JWSFactory;

class ExpirationTimeCheckerTest extends CheckerTestCase
{
    /** @var ExpirationTimeChecker */
    private $checker;

    public function setUp()
    {
        parent::setUp();

        $this->checker = new ExpirationTimeChecker();
    }

    public function testItReturnsEmptyArrayIfNoExpiryClaim()
    {
        $jws = JWSFactory::createJWS([]);

        $result = $this->checker->checkClaim($jws);

        $this->assertEquals([], $result);
    }

    public function testItThrowsExceptionIfTokenHasExpired()
    {
        $jws = JWSFactory::createJWS(['exp' => 1234]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The JWT has expired.');

        $this->checker->checkClaim($jws);
    }

    public function testItReturnsExpIfTokenIsStillValid()
    {
        $jws = JWSFactory::createJWS(['exp' => 64625299200]); // 11/23/4017 @ 12:00am (UTC)

        $result = $this->checker->checkClaim($jws);

        $this->assertEquals(['exp'], $result);
    }

    public function testItReturnsOkIfExpiryWithinTolerance()
    {
        $expiryTime = 1000;
        $tolerance = 300;
        $checker = new ExpirationTimeChecker($tolerance);
        $jws = JWSFactory::createJWS(['exp' => $expiryTime]);
        $this->mockCurrentTime($tolerance + $expiryTime);

        $result = $checker->checkClaim($jws);

        $this->assertEquals(['exp'], $result);
    }

    public function testItThrowsExceptionIfNegativeToleranceValueProvided()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Tolerance value must be >=0');

        new ExpirationTimeChecker(-100);
    }
}
