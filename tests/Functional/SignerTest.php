<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Test\Functional;

use Jose\Component\Core\JWAManager;
use Jose\Component\Core\JWAManagerFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWSFactory;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Test\TestCase;
use Jose\Component\Signature\Verifier;

/**
 * @group Signer
 * @group Functional
 */
final class SignerTest extends TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No "alg" parameter set in the header.
     */
    public function testAlgParameterIsMissing()
    {
        $signatureAlgorithmManager = JWAManager::create([]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload($this->getKey3())
            ->addSignature($this->getKey1(), []);

        $jwsBuilder->build();
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "foo" is not supported.
     */
    public function testAlgParameterIsNotSupported()
    {
        $signatureAlgorithmManager = JWAManager::create([]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);

        $jwsBuilder = $jwsBuilder
            ->withPayload($this->getKey3())
            ->addSignature($this->getKey1(), ['alg' => 'foo']);

        $jwsBuilder->build();
    }

    public function testSignAndLoadCompact()
    {
        $signatureAlgorithmManager = JWAManager::create([new HS512(), new RS512()]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload($this->getKey3())
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);

        $jws = $jwsBuilder->build();

        $this->assertEquals(2, $jws->countSignatures());

        $loaded = JWSLoader::load($jws->toJSON());

        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeader('alg'));
        $this->assertEquals('RS512', $loaded->getSignature(1)->getProtectedHeader('alg'));
    }

    public function testSignMultipleInstructionWithCompactRepresentation()
    {
        $signatureAlgorithmManager = JWAManager::create([new HS512(), new RS512()]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);

        $jws = $jwsBuilder->build();

        $this->assertEquals(2, $jws->countSignatures());
        $this->assertEquals('eyJhbGciOiJIUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $jws->toCompactJSON(0));
        $this->assertEquals('eyJhbGciOiJSUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $jws->toCompactJSON(1));
    }

    /**
     * @group JWSBuilder
     */
    public function testSignMultipleInstructionWithCompactRepresentationUsingBuilder()
    {
        $jwaManager = JWAManager::create([new HS512(), new RS512()]);
        $jwsBuilder = new JWSBuilder($jwaManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);
        $jws = $jwsBuilder->build();

        $this->assertEquals(2, $jws->countSignatures());
        $this->assertEquals('eyJhbGciOiJIUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $jws->toCompactJSON(0));
        $this->assertEquals('eyJhbGciOiJSUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $jws->toCompactJSON(1));
    }

    /**
     * @group JWSBuilder
     */
    public function testSignMultipleInstructionWithCompactRepresentationUsingBuilderAndDetachedPayload()
    {
        $jwaManager = JWAManager::create([new HS512(), new RS512()]);
        $jwsBuilder = new JWSBuilder($jwaManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload('Live long and Prosper.', true)
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);
        $jws = $jwsBuilder->build();

        $this->assertEquals(2, $jws->countSignatures());
        $this->assertEquals('eyJhbGciOiJIUzUxMiJ9..TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $jws->toCompactJSON(0));
        $this->assertEquals('eyJhbGciOiJSUzUxMiJ9..cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $jws->toCompactJSON(1));
    }

    public function testCreateCompactJWSUsingFactory()
    {
        $jws0 = JWSFactory::createJWSToCompactJSON('Live long and Prosper.', $this->getKey1(), ['alg' => 'HS512']);
        $jws1 = JWSFactory::createJWSToCompactJSON('Live long and Prosper.', $this->getKey2(), ['alg' => 'RS512']);
        $jws2 = JWSFactory::createJWSWithDetachedPayloadToCompactJSON('Live long and Prosper.', $this->getKey1(), ['alg' => 'HS512']);
        $jws3 = JWSFactory::createJWSWithDetachedPayloadToCompactJSON('Live long and Prosper.', $this->getKey2(), ['alg' => 'RS512']);

        $this->assertEquals('eyJhbGciOiJIUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $jws0);
        $this->assertEquals('eyJhbGciOiJSUzUxMiJ9.TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg.cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $jws1);
        $this->assertEquals('eyJhbGciOiJIUzUxMiJ9..TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ', $jws2);
        $this->assertEquals('eyJhbGciOiJSUzUxMiJ9..cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA', $jws3);

        $algorithmManager = JWAManagerFactory::createFromAlgorithmName(['HS512', 'RS512']);
        $verifier = new Verifier($algorithmManager);
        $loaded_0 = JWSLoader::load($jws0);
        $verifier->verifyWithKey($loaded_0, $this->getKey1());

        $loaded_1 = JWSLoader::load($jws1);
        $verifier->verifyWithKey($loaded_1, $this->getKey2());

        $loaded_2 = JWSLoader::load($jws2);
        $verifier->verifyWithKey($loaded_2, $this->getKey1(), 'Live long and Prosper.');

        $loaded_3 = JWSLoader::load($jws3);
        $verifier->verifyWithKey($loaded_3, $this->getKey2(),'Live long and Prosper.');
    }

    public function testSignMultipleInstructionWithFlattenedRepresentation()
    {
        $signatureAlgorithmManager = JWAManager::create([new HS512(), new RS512()]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);
        $jws = $jwsBuilder->build();

        $this->assertEquals(2, $jws->countSignatures());
        $this->assertEquals('{"payload":"TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg","protected":"eyJhbGciOiJIUzUxMiJ9","signature":"TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ"}', $jws->toFlattenedJSON(0));
        $this->assertEquals('{"payload":"TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg","protected":"eyJhbGciOiJSUzUxMiJ9","signature":"cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA"}', $jws->toFlattenedJSON(1));
    }

    public function testCreateFlattenedJWSUsingFactory()
    {
        $jws0 = JWSFactory::createJWSToFlattenedJSON('Live long and Prosper.', $this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar']);
        $jws1 = JWSFactory::createJWSToFlattenedJSON('Live long and Prosper.', $this->getKey2(), ['alg' => 'RS512'], ['plic' => 'ploc']);
        $jws2 = JWSFactory::createJWSWithDetachedPayloadToFlattenedJSON('Live long and Prosper.', $this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar']);
        $jws3 = JWSFactory::createJWSWithDetachedPayloadToFlattenedJSON('Live long and Prosper.', $this->getKey2(), ['alg' => 'RS512'], ['plic' => 'ploc']);

        $this->assertEquals('{"payload":"TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg","protected":"eyJhbGciOiJIUzUxMiJ9","header":{"foo":"bar"},"signature":"TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ"}', $jws0);
        $this->assertEquals('{"payload":"TGl2ZSBsb25nIGFuZCBQcm9zcGVyLg","protected":"eyJhbGciOiJSUzUxMiJ9","header":{"plic":"ploc"},"signature":"cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA"}', $jws1);
        $this->assertEquals('{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"foo":"bar"},"signature":"TjxvVLKLc1kU5XW1NjZlI6_kQHjeU2orTWBZ7p0KuRzq_9lyPWR04PAUpbYkaLJLsmIJ8Fxi8Gsrc0khPtFxfQ"}', $jws2);
        $this->assertEquals('{"protected":"eyJhbGciOiJSUzUxMiJ9","header":{"plic":"ploc"},"signature":"cR-npy2oEi275rpeTAKooLRzOhIOFMewpzE38CLx4_CtdkN4Y7EUlca9ryV6yGMH8SswUqosMnmUU8XYg7xkuNAc6mCODJVF2exfb_Mulmr9YolQrLFrFRsMk1rztXMinCMQeCe5ue3Ck4E4aJlIkjf-d0DJktoIhH6d2gZ-iJeLQ32wcBhPcEbj2gr7K_wYKlEXhKFwG59OE-hIi9IHXEKvK-2V5vzZLVC80G4aWYd3D-2eX3LF1K69NP04jGcu1D4l9UV8zTz1gOWe697iZG0JyKhSccUaHZ0TfEa8cT0tm6xTz6tpUGSDdvPQU8JCU8GTOsi9ifxTsI-GlWE3YA"}', $jws3);

        $algorithmManager = JWAManagerFactory::createFromAlgorithmName(['HS512', 'RS512']);
        $verifier = new Verifier($algorithmManager);
        $loaded_0 = JWSLoader::load($jws0);
        $verifier->verifyWithKey($loaded_0, $this->getKey1());

        $loaded_1 = JWSLoader::load($jws1);
        $verifier->verifyWithKey($loaded_1, $this->getKey2());

        $loaded_2 = JWSLoader::load($jws2);
        $verifier->verifyWithKey($loaded_2, $this->getKey1(), 'Live long and Prosper.');

        $loaded_3 = JWSLoader::load($jws3);
        $verifier->verifyWithKey($loaded_3, $this->getKey2(), 'Live long and Prosper.');
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "RS512" is not allowed with this key.
     */
    public function testAlgorithmNotAllowedForTheKey()
    {
        $signatureAlgorithmManager = JWAManager::create([]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey5(), ['alg' => 'RS512']);
        $jwsBuilder->build();
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Key cannot be used to sign
     */
    public function testOperationNotAllowedForTheKey()
    {
        $signatureAlgorithmManager = JWAManager::create([new PS512()]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey4(), ['alg' => 'PS512']);

        $jwsBuilder->build();
    }

    public function testSignAndLoadFlattened()
    {
        $signatureAlgorithmManager = JWAManager::create([new HS512()]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload(['baz', 'ban'])
            ->addSignature($this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar']);

        $jws = $jwsBuilder->build();

        $loaded = JWSLoader::load($jws->toFlattenedJSON(0));

        $this->assertEquals(1, $loaded->countSignatures());
        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertTrue(is_array($loaded->getPayload()));
        $this->assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeader('alg'));
    }

    public function testSignAndLoad()
    {
        $signatureAlgorithmManager = JWAManager::create([new HS512(), new RS512()]);
        $verifier = new Verifier($signatureAlgorithmManager);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);

        $jws = $jwsBuilder->build();

        $loaded = JWSLoader::load($jws->toJSON());

        $this->assertEquals(2, $loaded->countSignatures());
        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertEquals('Live long and Prosper.', $loaded->getPayload());
        $verifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet());
        $verifier->verifyWithKeySet($loaded, $this->getPublicKeySet());

        $this->assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeader('alg'));
        $this->assertEquals('RS512', $loaded->getSignature(1)->getProtectedHeader('alg'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage  Unable to verify the JWS.
     */
    public function testSignAndLoadWithWrongKeys()
    {
        $signatureAlgorithmManager = JWAManager::create([new RS512()]);
        $verifier = new Verifier($signatureAlgorithmManager);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);

        $jws = $jwsBuilder->build();

        $loaded = JWSLoader::load($jws->toJSON());

        $this->assertEquals(1, $loaded->countSignatures());
        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertEquals('Live long and Prosper.', $loaded->getPayload());

        $verifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The algorithm "RS512" is not supported or is not a signature algorithm.
     */
    public function testSignAndLoadWithUnsupportedAlgorithm()
    {
        $verifier = new Verifier(JWAManager::create([new HS512()]));
        $jwsBuilder = new JWSBuilder(JWAManager::create([new RS512()]));
        $jwsBuilder = $jwsBuilder
            ->withPayload('Live long and Prosper.')
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);

        $jws = $jwsBuilder->build();

        $loaded = JWSLoader::load($jws->toJSON());

        $this->assertEquals(1, $loaded->countSignatures());
        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertEquals('Live long and Prosper.', $loaded->getPayload());

        $verifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage The JWS does not contain any signature.
     */
    public function testSignAndLoadWithJWSWithoutSignatures()
    {
        $signatureAlgorithmManager = JWAManager::create([new RS512()]);
        $verifier = new Verifier($signatureAlgorithmManager);
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $jws = '{"payload":"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4","signatures":[]}';

        $loaded = JWSLoader::load($jws);

        $this->assertEquals(0, $loaded->countSignatures());
        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertEquals($payload, $loaded->getPayload());

        $verifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet());
    }

    /**
     * @see https://tools.ietf.org/html/rfc7797#section-4
     * @see https://tools.ietf.org/html/rfc7797#section-4.2
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unable to convert the JWS with non-encoded payload.
     */
    public function testCompactJSONWithUnencodedPayload()
    {
        $payload = '$.02';
        $protected_header = [
            'alg'  => 'HS256',
            'b64'  => false,
            'crit' => ['b64'],
        ];

        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $expected_result = [
            'protected' => 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
            'payload'   => '$.02',
            'signature' => 'A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY',
        ];

        JWSFactory::createJWSToCompactJSON($payload, $key, $protected_header);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7797#section-4
     * @see https://tools.ietf.org/html/rfc7797#section-4.2
     */
    public function testCompactJSONWithUnencodedDetachedPayload()
    {
        $payload = '$.02';
        $protected_header = [
            'alg'  => 'HS256',
            'b64'  => false,
            'crit' => ['b64'],
        ];

        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $jws = JWSFactory::createJWSWithDetachedPayloadToCompactJSON($payload, $key, $protected_header);
        $this->assertEquals('eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY', $jws);

        $loaded = JWSLoader::load($jws);
        $algorithmManager = JWAManagerFactory::createFromAlgorithmName(['HS256']);
        $verifier = new Verifier($algorithmManager);
        $verifier->verifyWithKey($loaded, $key, $payload, $index);

        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertEquals(0, $index);
        $this->assertEquals($protected_header, $loaded->getSignature(0)->getProtectedHeaders());
    }

    /**
     * The library is able to support multiple payload encoding and conversion in JSON if payload is detached.
     */
    public function testCompactJSONWithUnencodedDetachedPayloadAndMultipleSignatures()
    {
        $payload = '$.02';
        $protected_header1 = [
            'alg'  => 'HS256',
            'b64'  => false,
            'crit' => ['b64'],
        ];
        $protected_header2 = [
            'alg'  => 'HS256',
        ];

        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $signatureAlgorithmManager = JWAManager::create([new HS256()]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload($payload, true)
            ->addSignature($key, $protected_header1)
            ->addSignature($key, $protected_header2);

        $jws = $jwsBuilder->build();

        $expected_result = '{"signatures":[{"signature":"A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY","protected":"eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"},{"signature":"5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ","protected":"eyJhbGciOiJIUzI1NiJ9"}]}';

        $this->assertEquals($expected_result, $jws->toJSON());

        $loaded = JWSLoader::load($expected_result);
        $algorithmManager = JWAManagerFactory::createFromAlgorithmName(['HS256']);
        $verifier = new Verifier($algorithmManager);
        $verifier->verifyWithKey($loaded, $key, $payload, $index1);

        $this->assertEquals(0, $index1);
        $this->assertEquals($protected_header1, $loaded->getSignature(0)->getProtectedHeaders());
    }

    /**
     * The library is able to support multiple payload encoding and conversion in JSON is not available if payload is not detached.
     *
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage  Foreign payload encoding detected. The JWS cannot be converted.
     */
    public function testCompactJSONWithUnencodedPayloadAndMultipleSignatures()
    {
        $payload = '$.02';
        $protected_header1 = [
            'alg'  => 'HS256',
            'b64'  => false,
            'crit' => ['b64'],
        ];
        $protected_header2 = [
            'alg'  => 'HS256',
        ];

        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $signatureAlgorithmManager = JWAManager::create([new HS256()]);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload($payload)
            ->addSignature($key, $protected_header1)
            ->addSignature($key, $protected_header2);

        $jws = $jwsBuilder->build();

        $jws->toJSON();
    }

    /**
     * @expectedException \LogicException
     * @expectedExceptionMessage The protected header parameter "crit" is mandatory when protected header parameter "b64" is set.
     */
    public function testJWSWithUnencodedPayloadButNoCritHeader()
    {
        $payload = '$.02';
        $protected_header = [
            'alg'  => 'HS256',
            'b64'  => false,
        ];

        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        JWSFactory::createJWSWithDetachedPayloadToCompactJSON($payload, $key, $protected_header);
    }

    /**
     * @expectedException \LogicException
     * @expectedExceptionMessage The protected header parameter "crit" must be an array.
     */
    public function testJWSWithUnencodedPayloadButCritHeaderIsNotAnArray()
    {
        $payload = '$.02';
        $protected_header = [
            'alg'  => 'HS256',
            'b64'  => false,
            'crit' => 'foo',
        ];

        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        JWSFactory::createJWSWithDetachedPayloadToCompactJSON($payload, $key, $protected_header);
    }

    /**
     * @expectedException \LogicException
     * @expectedExceptionMessage The protected header parameter "crit" must contain "b64" when protected header parameter "b64" is set.
     */
    public function testJWSWithUnencodedPayloadButCritHeaderDoesNotContainB64()
    {
        $payload = '$.02';
        $protected_header = [
            'alg'  => 'HS256',
            'b64'  => false,
            'crit' => ['foo'],
        ];

        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        JWSFactory::createJWSWithDetachedPayloadToCompactJSON($payload, $key, $protected_header);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7797#section-4
     * @see https://tools.ietf.org/html/rfc7797#section-4.2
     */
    public function testFlattenedJSONWithUnencodedPayload()
    {
        $payload = '$.02';
        $protected_header = [
            'alg'  => 'HS256',
            'b64'  => false,
            'crit' => ['b64'],
        ];

        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $expected_result = [
            'protected' => 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
            'payload'   => '$.02',
            'signature' => 'A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY',
        ];

        $jws = JWSFactory::createJWSToFlattenedJSON($payload, $key, $protected_header);

        $this->assertEquals($expected_result, json_decode($jws, true));

        $loaded = JWSLoader::load($jws);
        $algorithmManager = JWAManagerFactory::createFromAlgorithmName(['HS256']);
        $verifier = new Verifier($algorithmManager);
        $verifier->verifyWithKey($loaded, $key, null, $index);

        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertEquals($payload, $loaded->getPayload());
        $this->assertEquals(0, $index);
        $this->assertEquals($protected_header, $loaded->getSignature(0)->getProtectedHeaders());
    }

    /**
     * @see https://tools.ietf.org/html/rfc7797#section-4
     * @see https://tools.ietf.org/html/rfc7797#section-4.2
     */
    public function testFlattenedJSONWithUnencodedDetachedPayload()
    {
        $payload = '$.02';
        $protected_header = [
            'alg'  => 'HS256',
            'b64'  => false,
            'crit' => ['b64'],
        ];

        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        $expected_result = [
            'protected' => 'eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19',
            'signature' => 'A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY',
        ];

        $jws = JWSFactory::createJWSWithDetachedPayloadToFlattenedJSON($payload, $key, $protected_header);

        $this->assertEquals($expected_result, json_decode($jws, true));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage No "alg" parameter set in the header.
     */
    public function testSignAndLoadWithoutAlgParameterInTheHeader()
    {
        $signatureAlgorithmManager = JWAManager::create([new RS512()]);
        $verifier = new Verifier($signatureAlgorithmManager);
        $payload = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept off to.";
        $jws = 'eyJraWQiOiJiaWxiby5iYWdnaW5zQGhvYmJpdG9uLmV4YW1wbGUifQ.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogoree7vjbU5y18kDquDg';

        $loaded = JWSLoader::load($jws);

        $this->assertEquals(1, $loaded->countSignatures());
        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertEquals($payload, $loaded->getPayload());

        $verifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet());
    }

    public function testSignAndLoadJWKSet()
    {
        $signatureAlgorithmManager = JWAManager::create([new HS512(), new RS512()]);
        $verifier = new Verifier($signatureAlgorithmManager);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload($this->getKeyset())
            ->addSignature($this->getKey1(), ['alg' => 'HS512'], ['foo' => 'bar'])
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);

        $jws = $jwsBuilder->build();

        $loaded = JWSLoader::load($jws->toJSON());
        $this->assertEquals(2, $loaded->countSignatures());
        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertEquals($this->getKeyset(), new JWKSet($loaded->getPayload()));
        $verifier->verifyWithKeySet($loaded, $this->getSymmetricKeySet());
        $verifier->verifyWithKeySet($loaded, $this->getPublicKeySet());

        $this->assertEquals('HS512', $loaded->getSignature(0)->getProtectedHeader('alg'));
        $this->assertEquals('RS512', $loaded->getSignature(1)->getProtectedHeader('alg'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage There is no key in the key set.
     */
    public function testKeySetIsEmpty()
    {
        $signatureAlgorithmManager = JWAManager::create([new HS512(), new RS512()]);
        $verifier = new Verifier($signatureAlgorithmManager);
        $jwsBuilder = new JWSBuilder($signatureAlgorithmManager);
        $jwsBuilder = $jwsBuilder
            ->withPayload($this->getKeyset())
            ->addSignature($this->getKey1(), ['alg' => 'HS512', ['foo' => 'bar']])
            ->addSignature($this->getKey2(), ['alg' => 'RS512']);

        $jws = $jwsBuilder->build();

        $loaded = JWSLoader::load($jws->toJSON());
        $this->assertEquals(2, $loaded->countSignatures());
        $this->assertInstanceOf(JWS::class, $loaded);
        $this->assertEquals($this->getKeyset(), new JWKSet($loaded->getPayload()));
        $verifier->verifyWithKeySet($loaded, new JWKSet());
        $verifier->verifyWithKey($loaded, JWK::create(['kty' => 'EC']));
    }

    /**
     * @return \Jose\Component\Core\JWK
     */
    protected function getKey1()
    {
        $key = JWK::create([
            'kty' => 'oct',
            'k'   => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
        ]);

        return $key;
    }

    /**
     * @return \Jose\Component\Core\JWK
     */
    protected function getKey2()
    {
        $key = JWK::create([
            'kty'     => 'RSA',
            'use'     => 'sig',
            'key_ops' => ['sign'],
            'n'       => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e'       => 'AQAB',
            'd'       => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p'       => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q'       => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp'      => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq'      => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi'      => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);

        return $key;
    }

    /**
     * @return \Jose\Component\Core\JWK
     */
    protected function getKey3()
    {
        $key = JWK::create([
            'kty'     => 'EC',
            'crv'     => 'P-256',
            'use'     => 'sig',
            'key_ops' => ['sign'],
            'x'       => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y'       => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            'd'       => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
        ]);

        return $key;
    }

    /**
     * @return \Jose\Component\Core\JWK
     */
    protected function getKey4()
    {
        $key = JWK::create([
            'kty'     => 'RSA',
            'alg'     => 'PS512',
            'key_ops' => ['encrypt', 'decrypt'],
            'n'       => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e'       => 'AQAB',
            'd'       => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p'       => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q'       => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp'      => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq'      => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi'      => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);

        return $key;
    }

    /**
     * @return \Jose\Component\Core\JWK
     */
    protected function getKey5()
    {
        $key = JWK::create([
            'kty'     => 'RSA',
            'alg'     => 'PS512',
            'use'     => 'sig',
            'n'       => 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
            'e'       => 'AQAB',
            'd'       => 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
            'p'       => '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
            'q'       => 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
            'dp'      => 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
            'dq'      => 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
            'qi'      => 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U',
        ]);

        return $key;
    }

    /**
     * @return \Jose\Component\Core\JWKSet
     */
    protected function getKeyset()
    {
        $keyset = new JWKSet();
        $keyset->addKey($this->getKey1());
        $keyset->addKey($this->getKey2());

        return $keyset;
    }
}
