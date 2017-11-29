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
use Jose\Checker\IssuedAtChecker;
use Jose\Factory\JWSFactory;

class IssuedAtCheckerTest extends CheckerTestCase
{
    /** @var IssuedAtChecker */
    private $checker;

    public function setUp()
    {
        parent::setUp();
        $this->checker = new IssuedAtChecker();
    }

    public function testItReturnsEmptyArrayIfNoIatClaim()
    {
        $jws = JWSFactory::createJWS([]);

        $result = $this->checker->checkClaim($jws);

        $this->assertEquals([], $result);
    }

    public function testItThrowsExceptionIfIssuedInTheFuture()
    {
        $jws = JWSFactory::createJWS(['iat' => '64625299200']); // 11/23/4017 @ 12:00am (UTC)

        $this->expectExceptionMessage('The JWT is issued in the future.');
        $this->expectException(InvalidArgumentException::class);

        $this->checker->checkClaim($jws);
    }

    public function testItReturnsOkIfIssuedInThePast()
    {
        $jws = JWSFactory::createJWS(['iat' => time() - 1000]);

        $result = $this->checker->checkClaim($jws);

        $this->assertEquals(['iat'], $result);
    }

    public function testItReturnsOkIfIssuedInFutureWithinTolerance()
    {
        $issuedAtTime = 1000;
        $tolerance = 300;
        $jws = JWSFactory::createJWS(['iat' => $issuedAtTime]);
        $this->mockCurrentTime($issuedAtTime - $tolerance);

        $checker = new IssuedAtChecker($tolerance);
        $result = $checker->checkClaim($jws);

        $this->assertEquals(['iat'], $result);
    }

    public function testItThrowsExceptionIfNegativeToleranceValueProvided()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Tolerance value must be >=0');

        new IssuedAtChecker(-100);
    }
}
