<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWEFactory;
use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;
use Jose\Loader;
use Jose\Object\JWEInterface;
use Jose\Object\JWSInterface;

/**
 * Class RSASignatureTest.
 *
 * @group RSA
 * @group Unit
 */
class RSAKeyWithoutAllPrimesTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param string $signature_algorithm
     *
     * @dataProvider dataSignatureAlgorithms
     */
    public function testSignatureAlgorithms($signature_algorithm)
    {
        $key = $this->getPrivateKey();

        $claims = ['foo' => 'bar'];

        $jws = JWSFactory::createJWSToCompactJSON($claims, $key, ['alg' => $signature_algorithm]);

        $loader = new Loader();

        $this->assertInstanceOf(JWSInterface::class, $loader->loadAndVerifySignatureUsingKey($jws, $key, [$signature_algorithm]));
    }

    /**
     * @return array
     */
    public function dataSignatureAlgorithms()
    {
        return [
            ['RS256'],
            ['RS384'],
            ['RS512'],
            ['PS256'],
            ['PS384'],
            ['PS512'],
        ];
    }

    /**
     * @param string $encryption_algorithm
     *
     * @dataProvider dataEncryptionAlgorithms
     */
    public function testEncryptionAlgorithms($encryption_algorithm)
    {
        $key = $this->getPrivateKey();

        $claims = ['foo' => 'bar'];

        $jws = JWEFactory::createJWEToCompactJSON($claims, $key, ['alg' => $encryption_algorithm, 'enc' => 'A256GCM']);

        $loader = new Loader();

        $this->assertInstanceOf(JWEInterface::class, $loader->loadAndDecryptUsingKey($jws, $key, [$encryption_algorithm], ['A256GCM']));
    }

    /**
     * @return array
     */
    public function dataEncryptionAlgorithms()
    {
        return [
            ['RSA1_5'],
            ['RSA-OAEP'],
            ['RSA-OAEP-256'],
        ];
    }

    private function getPrivateKey()
    {
        return JWKFactory::createFromValues(
            [
                'kty' => 'RSA',
                'kid' => 'private',
                'n'   => '2NRPORHXd7wPU6atHqmSfWgEPvsP8HVUkY2AwQQAc8x1J509X5HFxeSXnQym9eAnZHl0JCPbvHoPH4QHlvITYoh0MSgFm2aOPyqOD-XcNdKWtnNX2JIurUCyVlwSwtlmy2ZbCz8YuUmFO0iacahfK1wbWT5QoY-pU3UxnMzDhlBslZN5uL7nRE8Sh_8BthsrMdYeGIMY55kh-P7xTs3MHzpOKhFSrOhdN6aO3HWYUuMAdoMNB-hJvckb2PbCy0_K1Wm3SBHtXn-cuMIUF00W9AR3amp3u3hLa2rcz29jEFXTr2FxKyLH4SdlnFFMJl2vaXuxM4PXgLN33Kj34PfKgc8ljDJ7oaSI9bKt7gunXOLv_o4XWYDq91cvUkOIDAsvqxzzHPZBt0Hru7roW3btkUOiqR6RWy-Cw272yiSEC5QA93m_vklD1KajoFeWN0BW2lWGlfGieZldvKX0sumk1TZuLhlHPHSKYcpeCfahT-jLr1yAeHql6qRN_a0BiHu-SSSjts6InmF1pAELznZ3Jn9-QXX78LsY3xaqOlYqHbCohxXorlYRi4so6eMGILtXjqHOoISb13Ez4YNOQmV4ygmyABRkE0AQG5KLy5cZB7LZn7zqw869UjXxWrmiOaBeDqOkxww6qiWIEDwPIouRLwOfPFtC4LGlb9LmG9Hlhp8',
                'e'   => 'AQAB',
                'd'   => 'PsMls2VAsz3SSepjDg8Tgg1LvVc6w-WSdxc4f6ZC40H5X2AaVcGCN8f1QtZYta8Od_zX62Ydwq6qFftHnx-vEMRirZ_iD5td7VbKDDwCw-mTCnjUorGdpTSm6mx4WcJICPQ1wkmfRHLNh916JxAPjCN7Hxf0iu9kme3AUJzMs-IvrBQmFZ3cn18sBAWCX0358NEDoSDBYrhmpwZUnvTe8uMToQWmoroX0XX6wEGht8xRY_yHFxTb032U-_ZhaCxOj_uru8bEqKfTm39CBYSg8j0gu8LZqYAmhI9IHxsk16OgRJG2CkBlDv0yYk799dUEY0oUfs7Y4D4SoeKe7ZWMHgKMEqa7ONz18ORznxqKSQhi4hfNVgwMzaM0IoYP4KOfHuaK263zhJU0hMzURJ8KifECeOsDHBR6BhLJ9TYzUe4c9UU55nFNgRBwknKHFFrRAsgVETEzmZWHzWwGQIFtKIAVZ1cjkdMEL3BlbzzXVofXfbbCrPQqcABYx2BZ-J_P8-UFjeMo83VLrR5IHj0_8IhQZUmxZYJcpTIwrf-1A4JGlN2_eLqRymF8tZI6zIPJyo1C0M1CIB3EeHzi-70SbF8xFtGUB7hR234yo_SM-KqVdIk2Sjjta2bQ1KXjSEcvrS_358AMiP0-9JT_fHxTCyzra-SNYoZhdnrEFzoVwQE',
                'p'   => '6fWvnj34kJtfMnO1j-qbPjFnaTevREBGAypMvUBU3Fx1Xx0nE7zdc7lln2Qq5-yTQtOQ2lpiE69HkQLR4pMU6V44SjFgVzcTzbFCnNgknEV54S5dyp4KojSWxBi6bt5GwaACkiElDEw9wgc-8JgaEkv4F7e-w44HBwPDECTjE_N0vIawpbD_y6zpifB8ziaAI3xTG4ssA1dt8WZuyQW8SR4FRsYnfkqy0twwHn02gs7XSl4NepkhSO7CY5-YC3U6LazAEZi2NTiUuZSw7F6KaRhsA8CnXTDE5JqFks_fXfLNCbtClON2JtrB1zY-l-2bHyh2a6unDtGn9ZN-Ec7BXw',
                'q'   => '7UF_NblAyTxmj7Z2Jz1sZmz-Q3YHOcta00DjmHBhR9ItYRMQFMj-SUGPAtwvN-sk3_ThugaQt46SLT_I3Gy8433cHdW7o3So6HiMYVunyfhqnWznSWs6SvIoEh8rJOXkkIZ-DlRP8XyW5OOvi0cbWEQ1f1jbFyistMmnBClPvf2TKKPvShUl9qmvLxuU87j-_bgQmjVmtwZadnPOyPAxQ4_qqSfIiTOvMSxSycr58rTyu3khHQapGHkS5-2Y_w40GUSfVJ3XP48delYpK-PZP71hn89MJTnnfPOtvJAk1wbEev5wQFTJd-PGOudkGkuEIXryF4TGxRPltl5UeF0CwQ',
            ]
        );
    }
}
