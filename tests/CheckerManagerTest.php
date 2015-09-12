<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace SpomkyLabs\Test;

/**
 * @group CheckerManager
 */
class CheckerManagerTest extends TestCase
{
    /**
     * @expectedException \Exception
     * @expectedExceptionMessage Issuer not allowed.
     */
    public function testCheckJWTWithBadIssuer()
    {
        $jwt = $this->getJWTManager()->createJWT();
        $jwt->setPayload([
            'exp' => time() + 10000,
            'iss' => 'foo',
            'sub' => 'SUB2',
            'aud' => 'My service',
            'iat' => time() - 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }

    /**
     * @expectedException \Exception
     * @expectedExceptionMessage Bad audience.
     */
    public function testCheckJWTWithBadAudience()
    {
        $jwt = $this->getJWTManager()->createJWT();
        $jwt->setPayload([
            'exp' => time() + 10000,
            'iss' => 'ISS1',
            'sub' => 'SUB2',
            'aud' => 'foo',
            'iat' => time() - 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }

    /**
     * @expectedException \Exception
     * @expectedExceptionMessage The JWT has expired.
     */
    public function testCheckExpiredJWT()
    {
        $jwt = $this->getJWTManager()->createJWT();
        $jwt->setPayload([
            'exp' => time() - 10000,
            'iss' => 'ISS1',
            'sub' => 'SUB2',
            'aud' => 'My service',
            'iat' => time() - 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }

    /**
     * @expectedException \Exception
     * @expectedExceptionMessage The JWT is issued in the futur.
     */
    public function testCheckJWTIssuedInTheFutur()
    {
        $jwt = $this->getJWTManager()->createJWT();
        $jwt->setPayload([
            'exp' => time() + 10000,
            'iss' => 'ISS1',
            'sub' => 'SUB2',
            'aud' => 'My service',
            'iat' => time() + 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }

    /**
     * @expectedException \Exception
     * @expectedExceptionMessage Can not use this JWT yet.
     */
    public function testCheckJWTNotYetUsable()
    {
        $jwt = $this->getJWTManager()->createJWT();
        $jwt->setPayload([
            'exp' => time() + 10000,
            'iss' => 'ISS1',
            'sub' => 'SUB2',
            'aud' => 'My service',
            'iat' => time() - 10000,
            'nbf' => time() + 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }

    /**
     * @expectedException \Exception
     * @expectedExceptionMessage Invalid subject.
     */
    public function testCheckJWTWithBadSubject()
    {
        $jwt = $this->getJWTManager()->createJWT();
        $jwt->setPayload([
            'exp' => time() + 10000,
            'iss' => 'ISS1',
            'sub' => 'foo',
            'aud' => 'My service',
            'iat' => time() - 10000,
            'nbf' => time() - 10000,
        ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }

    public function testCheckValidJWT()
    {
        $jwt = $this->getJWTManager()->createJWT();
        $jwt->setPayload([
                'exp' => time() + 10000,
                'iss' => 'ISS1',
                'sub' => 'SUB2',
                'aud' => 'My service',
                'iat' => time() - 10000,
                'nbf' => time() - 10000,
            ]);

        $this->getCheckerManager()->checkJWT($jwt);
    }
}
