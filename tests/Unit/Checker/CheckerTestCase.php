<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Unit\Checker {
    use Jose\Checker\Clock;
    use PHPUnit\Framework\TestCase;

    abstract class CheckerTestCase extends TestCase
    {
        public function tearDown()
        {
            Clock::$mockedTime = false;
        }

        protected function mockCurrentTime($unixTime)
        {
            Clock::$mockedTime = (int) $unixTime;
        }
    }
}

namespace Jose\Checker {
    class Clock
    {
        public static $mockedTime = false;
    }

    function time()
    {
        if (Clock::$mockedTime) {
            return Clock::$mockedTime;
        }

        return \time();
    }
}
