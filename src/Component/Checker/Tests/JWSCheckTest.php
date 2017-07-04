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

namespace Jose\Component\Checker\Tests;

use Base64Url\Base64Url;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\CheckerManager;
use Jose\Component\Checker\CriticalHeaderChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Checker\Tests\Stub\IssuerChecker;
use Jose\Component\Checker\Tests\Stub\JtiChecker;
use Jose\Component\Checker\Tests\Stub\SubjectChecker;
use Jose\Component\Signature\JWS;
use PHPUnit\Framework\TestCase;

/**
 * @group CheckerManager
 * @group Functional
 */
final class JWSCheckTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT has expired.
     */
    public function testExpiredJWS()
    {
        $payload = ['exp' => time() - 1];
        $headers = ['alg' => 'none'];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT is issued in the future.
     */
    public function testJWSIssuedInTheFuture()
    {
        $payload = ['iat' => time() + 100];
        $headers = ['alg' => 'none'];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));
        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT can not be used yet.
     */
    public function testJWSNotNow()
    {
        $payload = ['nbf' => time() + 100];
        $headers = ['alg' => 'none'];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testJWSNotForAudienceWithAudienceAsString()
    {
        $payload = ['aud' => 'Other Service'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testJWSNotForAudienceWithAudienceAsArray()
    {
        $payload = ['aud' => ['Other Service']];
        $headers = ['alg' => 'none'];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage One or more claims are marked as critical, but they are missing or have not been checked (["iss"]).
     */
    public function testJWSHasCriticalClaimsNotSatisfied()
    {
        $payload = [];
        $headers = ['alg' => 'none', 'crit' => ['iss']];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The issuer "foo" is not allowed.
     */
    public function testJWSBadIssuer()
    {
        $payload = ['iss' => 'foo'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The subject "foo" is not allowed.
     */
    public function testJWSBadSubject()
    {
        $payload = ['sub' => 'foo'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid token ID "bad jti".
     */
    public function testJWSBadTokenID()
    {
        $payload = ['jti' => 'bad jti'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    public function testJWSSuccessfullyCheckedWithCriticalHeaders()
    {
        $payload = ['jti' => 'JTI1', 'exp' => time() + 3600, 'iat' => time() - 100, 'nbf' => time() - 100, 'iss' => 'ISS1', 'sub' => 'SUB1', 'aud' => ['My Service']];
        $headers = ['alg' => 'none', 'crit' => ['exp', 'iss', 'sub', 'aud', 'jti']];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    public function testJWSSuccessfullyCheckedWithUnsupportedClaims()
    {
        $payload = ['foo' => 'bar'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create($payload)
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @var CheckerManager|null
     */
    private $checker_manager = null;

    /**
     * @return CheckerManager
     */
    private function getCheckerManager(): CheckerManager
    {
        if (null === $this->checker_manager) {
            $this->checker_manager = new CheckerManager();
            $this->checker_manager->addClaimChecker(new ExpirationTimeChecker());
            $this->checker_manager->addClaimChecker(new IssuedAtChecker());
            $this->checker_manager->addClaimChecker(new NotBeforeChecker());
            $this->checker_manager->addClaimChecker(new AudienceChecker('My Service'));
            $this->checker_manager->addClaimChecker(new SubjectChecker());
            $this->checker_manager->addClaimChecker(new IssuerChecker());
            $this->checker_manager->addClaimChecker(new JtiChecker());
            $this->checker_manager->addHeaderChecker(new CriticalHeaderChecker());
        }

        return $this->checker_manager;
    }
}
