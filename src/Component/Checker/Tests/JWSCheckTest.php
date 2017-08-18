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
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Checker\Tests\Stub\IssuerChecker;
use Jose\Component\Checker\Tests\Stub\JtiChecker;
use Jose\Component\Checker\Tests\Stub\SubjectChecker;
use Jose\Component\Signature\JWS;
use PHPUnit\Framework\TestCase;

/**
 * @group ClaimCheckerManager
 * @group Functional
 */
final class JWSCheckTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The header contains duplicated entries: ["alg"].
     */
    public function testDuplicatedHeaderParameters()
    {
        $payload = ['exp' => time() + 1000];
        $protected = ['alg' => 'none'];
        $unprotected = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature(
                '',
                Base64Url::encode(json_encode($protected)),
                $unprotected
            );

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT has expired.
     */
    public function testExpiredJWS()
    {
        $payload = ['exp' => time() - 1];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT is issued in the future.
     */
    public function testJWSIssuedInTheFuture()
    {
        $payload = ['iat' => time() + 100];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));
        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWT can not be used yet.
     */
    public function testJWSNotNow()
    {
        $payload = ['nbf' => time() + 100];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testJWSNotForAudienceWithAudienceAsString()
    {
        $payload = ['aud' => 'Other Service'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Bad audience.
     */
    public function testJWSNotForAudienceWithAudienceAsArray()
    {
        $payload = ['aud' => ['Other Service']];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage One or more headers are marked as critical, but they are missing or have not been checked: ["iss"].
     */
    public function testJWSHasCriticalClaimsNotSatisfied()
    {
        $payload = [];
        $headers = ['alg' => 'none', 'crit' => ['iss']];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The issuer "foo" is not allowed.
     */
    public function testJWSBadIssuer()
    {
        $payload = ['iss' => 'foo'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The subject "foo" is not allowed.
     */
    public function testJWSBadSubject()
    {
        $payload = ['sub' => 'foo'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid token ID "bad jti".
     */
    public function testJWSBadTokenID()
    {
        $payload = ['jti' => 'bad jti'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
    }

    public function testJWSSuccessfullyCheckedWithCriticalHeaders()
    {
        $payload = ['jti' => 'JTI1', 'exp' => time() + 3600, 'iat' => time() - 100, 'nbf' => time() - 100, 'iss' => 'ISS1', 'sub' => 'SUB1', 'aud' => ['My Service']];
        $headers = ['alg' => 'none', 'jti' => 'JTI1', 'exp' => time() + 3600, 'crit' => ['exp', 'jti']];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
        $this->assertEquals(json_encode($payload), $jws->getPayload());
    }

    public function testJWSSuccessfullyCheckedWithUnsupportedClaims()
    {
        $payload = ['foo' => 'bar'];
        $headers = ['alg' => 'none'];
        $jws = JWS::create(json_encode($payload))
            ->addSignature('', Base64Url::encode(json_encode($headers)));

        $this->getClaimCheckerManager()->check($jws);
        $this->getHeaderCheckerManager()->check($jws, 0);
        $this->assertEquals(json_encode($payload), $jws->getPayload());
    }

    /**
     * @var ClaimCheckerManager|null
     */
    private $claim_checker_manager = null;

    /**
     * @return ClaimCheckerManager
     */
    private function getClaimCheckerManager(): ClaimCheckerManager
    {
        if (null === $this->claim_checker_manager) {
            $this->claim_checker_manager = new ClaimCheckerManager();
            $this->claim_checker_manager->add(new ExpirationTimeChecker());
            $this->claim_checker_manager->add(new IssuedAtChecker());
            $this->claim_checker_manager->add(new NotBeforeChecker());
            $this->claim_checker_manager->add(new AudienceChecker('My Service'));
            $this->claim_checker_manager->add(new SubjectChecker());
            $this->claim_checker_manager->add(new IssuerChecker());
            $this->claim_checker_manager->add(new JtiChecker());
        }

        return $this->claim_checker_manager;
    }

    /**
     * @var HeaderCheckerManager|null
     */
    private $header_checker_manager = null;

    /**
     * @return HeaderCheckerManager
     */
    private function getHeaderCheckerManager(): HeaderCheckerManager
    {
        if (null === $this->header_checker_manager) {
            $this->header_checker_manager = new HeaderCheckerManager();
            $this->header_checker_manager->add(new ExpirationTimeChecker());
            $this->header_checker_manager->add(new IssuedAtChecker());
            $this->header_checker_manager->add(new NotBeforeChecker());
            $this->header_checker_manager->add(new AudienceChecker('My Service'));
            $this->header_checker_manager->add(new SubjectChecker());
            $this->header_checker_manager->add(new IssuerChecker());
            $this->header_checker_manager->add(new JtiChecker());
        }

        return $this->header_checker_manager;
    }
}
