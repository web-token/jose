<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Checker\Tests;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\CheckerManager;
use Jose\Component\Checker\CriticalHeaderChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Signature\JWSFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Checker\Tests\Stub\IssuerChecker;
use Jose\Component\Checker\Tests\Stub\JtiChecker;
use Jose\Component\Checker\Tests\Stub\SubjectChecker;
use PHPUnit\Framework\TestCase;

/**
 * @group CheckerManager
 * @group Functional
 */
final class CheckerManagerTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT has expired.
     */
    public function testExpiredJWT()
    {
        $jws = JWSFactory::createJWS(
            [
                'exp' => time() - 1,
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'alg' => 'HS512',
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT is issued in the future.
     */
    public function testJWTIssuedInTheFuture()
    {
        $jws = JWSFactory::createJWS(
            [
                'exp' => time() + 3600,
                'iat' => time() + 100,
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'alg' => 'HS512',
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT can not be used yet.
     */
    public function testJWTNotNow()
    {
        $jws = JWSFactory::createJWS(
            [
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() + 100,
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'alg' => 'HS512',
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testJWTNotForAudience()
    {
        $jws = JWSFactory::createJWS(
            [
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() - 100,
                'aud' => 'Other Service',
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'alg' => 'HS512',
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testJWTNotForAudience2()
    {
        $jws = JWSFactory::createJWS(
            [
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() - 100,
                'aud' => ['Other Service'],
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'alg' => 'HS512',
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testJWTNotForAudience3()
    {
        $jws = JWSFactory::createJWS(
            [
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() - 100,
                'aud' => ['Other Service'],
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'alg' => 'HS512',
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage One or more claims are marked as critical, but they are missing or have not been checked (["iss"]).
     */
    public function testJWTHasCriticalClaimsNotSatisfied()
    {
        $jws = JWSFactory::createJWS(
            [
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() - 100,
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'HS512',
                'zip' => 'DEF',
                'crit' => ['exp', 'iss'],
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The issuer "foo" is not allowed.
     */
    public function testJWTBadIssuer()
    {
        $jws = JWSFactory::createJWS(
            [
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() - 100,
                'iss' => 'foo',
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'HS512',
                'zip' => 'DEF',
                'crit' => ['exp', 'iss'],
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The subject "foo" is not allowed.
     */
    public function testJWTBadSubject()
    {
        $jws = JWSFactory::createJWS(
            [
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() - 100,
                'iss' => 'ISS1',
                'sub' => 'foo',
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'HS512',
                'zip' => 'DEF',
                'crit' => ['exp', 'iss', 'sub', 'aud'],
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid token ID "bad jti".
     */
    public function testJWTBadTokenID()
    {
        $jws = JWSFactory::createJWS(
            [
                'jti' => 'bad jti',
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() - 100,
                'iss' => 'ISS1',
                'sub' => 'SUB1',
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'HS512',
                'zip' => 'DEF',
                'crit' => ['exp', 'iss', 'sub', 'aud', 'jti'],
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    public function testJWTSuccessfullyCheckedWithCriticalHeaders()
    {
        $jws = JWSFactory::createJWS(
            [
                'jti' => 'JTI1',
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() - 100,
                'iss' => 'ISS1',
                'sub' => 'SUB1',
                'aud' => ['My Service'],
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'HS512',
                'zip' => 'DEF',
                'crit' => ['exp', 'iss', 'sub', 'aud', 'jti'],
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    public function testJWTSuccessfullyCheckedWithoutCriticalHeaders()
    {
        $jws = JWSFactory::createJWS(
            [
                'jti' => 'JTI1',
                'exp' => time() + 3600,
                'iat' => time() - 100,
                'nbf' => time() - 100,
                'iss' => 'ISS1',
                'sub' => 'SUB1',
                'aud' => ['My Service'],
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'HS512',
                'zip' => 'DEF',
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    public function testJWTSuccessfullyCheckedWithUnsupportedClaims()
    {
        $jws = JWSFactory::createJWS(
            [
                'foo' => 'bar',
            ]
        );
        $jws = $jws->addSignatureInformation(
            JWK::create(['kty' => 'none']),
            [
                'enc' => 'A256CBC-HS512',
                'alg' => 'HS512',
                'zip' => 'DEF',
            ]
        );

        $this->getCheckerManager()->checkJWS($jws, 0);
    }

    /**
     * @var \Jose\Component\Checker\CheckerManager|null
     */
    private $checker_manager = null;

    /**
     * @return \Jose\Component\Checker\CheckerManager
     */
    private function getCheckerManager()
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
