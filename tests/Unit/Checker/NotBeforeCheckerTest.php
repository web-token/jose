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
use Jose\Checker\NotBeforeChecker;
use Jose\Factory\JWSFactory;

class NotBeforeCheckerTest extends CheckerTestCase
{
    /** @var NotBeforeChecker */
    private $checker;

    public function setUp()
    {
        parent::setUp();

        $this->checker = new NotBeforeChecker();
    }

    public function testItReturnsEmptyArrayIfNoNbfClaim()
    {
        $jws = JWSFactory::createJWS([]);

        $result = $this->checker->checkClaim($jws);
        $this->assertEquals([], $result);
    }

    public function testItThrowsExceptionIfCurrentTimeIsBeforeNotBeforeClaim()
    {
        $jws = JWSFactory::createJWS(['nbf' => time() + 1000]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The JWT can not be used yet.');

        $this->checker->checkClaim($jws);
    }

    public function testItReturnsOkIfCurrentTimeAfterNbfClaim()
    {
        $notBefore = time();
        $tolerance = 300;
        $jws = JWSFactory::createJWS(['nbf' => $notBefore]);
        $checker = new NotBeforeChecker($tolerance);
        $this->mockCurrentTime($notBefore - $tolerance);

        $result = $checker->checkClaim($jws);

        $this->assertEquals(['nbf'], $result);
    }

    public function testItThrowsExceptionIfNegativeToleranceValueProvided()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Tolerance value must be >=0');

        new NotBeforeChecker(-100);
    }
}