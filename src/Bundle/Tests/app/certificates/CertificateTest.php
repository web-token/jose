<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\KeyConverter\KeyConverter;

/**
 * These tests will try to load certificates from PEM and DER files.
 * Certificates could contain an RSA or ECC key.
 *
 * @see http://fm4dd.com/openssl/certexamples.htm
 *
 * @group Certificate
 * @group Unit
 */
class CertificateTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage File "file:///foo/bar" does not exist.
     */
    public function testFileNotFound()
    {
        KeyConverter::loadKeyFromCertificateFile('file:///foo/bar');
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testFileNotValid()
    {
        KeyConverter::loadKeyFromCertificateFile('file://'.__DIR__.__FILE__);
    }

    /**
     * @dataProvider dataLoadCertificate
     */
    public function testLoadCertificate($file, array $expected_values)
    {
        $result = KeyConverter::loadKeyFromCertificateFile($file);

        $this->assertEquals($expected_values, $result);
    }

    public function dataLoadCertificate()
    {
        return [
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'PEM'.DIRECTORY_SEPARATOR.'512b-rsa-example-cert.pem',
                [
                    'kty'     => 'RSA',
                    'n'       => 'm_xmkHmEQrurE_0re_jeFRLl8ZPjBop7uLHhnia7lQG_5zDtZIUC3RVpqDSwBuw_NTweGyuP-o8AG98HxqxTBw',
                    'e'       => 'AQAB',
                    'x5t'     => 'Bxy5TwzIUU0CQSRwjuiyaHvX2dU',
                    'x5t#256' => 'Xw-1FmWBquZKEBwVg7G-vnToFKkeeooUuh6DXXj26ec',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'PEM'.DIRECTORY_SEPARATOR.'1024b-rsa-example-cert.pem',
                [
                    'kty'     => 'RSA',
                    'n'       => 'xgEGvHk-U_RY0j9l3MP7o-S2a6uf4XaRBhu1ztdCHz8tMG8Kj4_qJmgsSZQD17sRctHGBTUJWp4CLtBwCf0zAGVzySwUkcHSu1_2mZ_w7Nr0TQHKeWr_j8pvXH534DKEvugr21DAHbi4c654eLUL-JW_wJJYqJh7qHM3W3Fh7ys',
                    'e'       => 'AQAB',
                    'x5t'     => '4bK45ewZ00Wk-a_shpTw2cCqJc8',
                    'x5t#256' => '5F5GTPOxBGAOsVyuYzqUBjri0R2YDTiDowiQbs6oGgU',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'PEM'.DIRECTORY_SEPARATOR.'2048b-rsa-example-cert.pem',
                [
                    'kty'     => 'RSA',
                    'n'       => 'tM_RXjMp7AvPrnb1_i3ImcZ4ebkY-AvUurTXngJSBgn0GJNM1HDRQqApE5JzUHf2BImsAyzW8QarrWzA2dWmq8rNWtJWJlHlSwiKr8wZDyU0kLAqKUEPVfFrk9uds8zc7OvHVRjXQiXeSTUUMpKcHsZp4zz79Jr4-4vF4Bt-_U8luj_llleaJHlJFyfXiUtqLg2HUdkjPQaFVvhYMQ7ugZl4aM1uRH7J2oxaexy_JEApSNEDnO_cripd-Pdqx-m8xbBZ9pX8FsvYnO3D_BKQk3hadbRWg_r8QYT2ZHk0NRyseoUOc3hyAeckiSWe2n9lvK-HkxmM23UVtuAwxwj4WQ',
                    'e'       => 'AQAB',
                    'x5t'     => 'y17eUFeZUYeOLmcTxTvpOOsjfkA',
                    'x5t#256' => 'B4plbjZwSZyZG7AnRoIFive9wF_EYsYF8PiVgXmBbNc',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'PEM'.DIRECTORY_SEPARATOR.'4096b-rsa-example-cert.pem',
                [
                    'kty'     => 'RSA',
                    'n'       => 'sL1iEzi3sk20tUP1GnKniCyCtelBy70spiJW24k-5qQ-EjMAd-N8aSJVzeuHwtGNcpU-iy3l-ErewHCaxiFdwDJiXLA7Dc4KOe-y6rTb5zpCx9BqI4rBRCkIkRF-oDoKvbVkqsGhDXHExLAF7legENUk_hterNNIjfdoY1_Vf1eurJ0cE7Cf6eFkaS0nQI-Nu9oYjNfaiIPc64fdntq0MuxP1EoVuIKTq4YNn-n3AgZvmlyIGvqsWki3IXA1Lz166SMU3fzlkNt0IbyBM5Bmz5QQPCezcPSgsmsW2DARW9YtJQY8Ci45nKIoYiOz1bYQDrvwe9Q9oSnBYyqX7-A9VGpv9FbpisIcLoWVTYy6tQUdRSkSdQoqCxuMAk69C1YLb71MoRa0vtz3VEdE-R5QEFjzMkAx4AqWzh1tMHNIW7jXjv5UvNi44nhjRcSpjARRfZbDds7AOkMN9l5G9vxBZbVwrabjsFc7XZODA652g18vczGbqhR6b-ZVk2w1cA3chEDXJWJWwBGw3rxEKP6wDmRZfeDLut6wIC4j3mTeCHUv-PKK-SmkGgjntA7gG-BljSEONnGEOU7BB1rfhSDgDEqX_YTT4w3rtbn3-NAzrbIshnl_TVYqirbbWh6b3e629s7GrG3ABlJfnzUCY-KiJj0gfU4amaj07pBHDPzbW3k',
                    'e'       => 'AQAB',
                    'x5t'     => 'IBO6381r3QWOObmNaxF36HBgO5M',
                    'x5t#256' => 'yVWIatQnBpbU9lUGZmRlGg2bldGtJPpqQXfq3LhBq3M',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'PEM'.DIRECTORY_SEPARATOR.'8192b-rsa-example-cert.pem',
                [
                    'kty'     => 'RSA',
                    'n'       => 'q5lcEwG8rUflI1aL6omAaF5R1DFkCMllFaQ3HUwlwCWYNNyKxF1G2e-P3Y6SFWyp0sFfmDcvuebOY_Dw3KlC756bQUMEXH6TaubYDcXaKDyrdKgCSoufjhwHkNpRz3VxpkLADJQIHdijes2JN3daGARxSJLcjoSaZvq_LBCIHTTDGESBXJP6RtbjAjGjuLUgmcvkl029Xl8ylkrcibjTzXmOod3vioTnX5aZNT1c7evmskvixWG1NlHOhZ1HdXiPHLjKxnr4lHl9lxtTjkNSsF-Nz0bYHCpWZ9u98nkgvFAxNUmiwX5nHIqo39AK8YVuVmDGYzY-dPtD1UtCBXgj-Ryq1cPU66H7kEfvbn1kZRF0XcxqIUVDlpa_h4Aq7r8KnQ6nVF59oM8AwsrRu3llvlRzNCaRUhafZ6YUHR19j_6GpAJtOWwwV5m2qKs9EhfL9Kvz9DqWh3DBt0CuGIDS0NuBAt2_RmNQBP1u7L8pYZ_9kV-Y7YM9ocbuYpUbTy4vio33Pl2wG8iozgPIgOcbne4Vh4TGpe0hbXaL-a_84CVOWX4JyLxyBEWGB6PLfH74NyXyvh57X6Cn3P0Xr2rSgPEgEEovw5i9qDeqqzeO-GvUouhQjZgURP5USjd120IPjVoZP8RPRCAPUBQSUmi2dyHANRI3ydIhTKOEdZCVvIlVNu33wfN55kEeLCXBiDvfvozUbCGuuOkbs5Yz7vE8K9xlU_Xo2icptY_u3XMPW6YKRP6lvGtovn9295vENHOJDFCVkcJ819vHVqJnoiGAf_QX0J74NLm6fnWboH6-5BcIDl18uB3qEFAlneRflIrC2XBZju-dTuTaHy14WvVJNjTMUBgVQ4gaS1X2wmAztwv-Rk8o6k-KJuSZDWVEZyH3NaddkYSVONOMzIuuClbg4cEgLP2cxxqz8JdnyT2NNfMdGfxP4Nd_RvPtTD9kTVewlurzYVjoi8CC6VhV2Tgcp-UvT6Z0Yne-65dXi31VRqQWG8adWQ3gc9NP1oXfJqVt26ldXF9AVf7PcFcm7xzr2mwZKY-DMk1m1hBvUGeg7Iab34OABOY6J4AxXiXqKx3JV24SFydaSSevsulSrmUJU3g8TR-WwTh06Yp8DZplCU9MEvfyUSShtHED72anVRgVe8jw47k9TavJ-hPiAq0HUmmKGUeKvrqWN4bMpSiMCmHTkcqS_d4Dn4ZAI8W0DIluc9sXBaiUUSIt6t7gGNOZGUyZ-ZN4GNxVlMazB6CieGRhoPfRmXw7wq0k2R5BU1Q8PSj8jrZ88DgdfENnWCGy6Aq450OwfufGaHZDwAUD1kUoRGBkzIxvkWLVdQtmP4iZXOLSany0RtPZLGjSH-x0vQ',
                    'e'       => 'AQAB',
                    'x5t'     => 'YV6dSQ9sNS7rhNWcj-M4XuMmOE4',
                    'x5t#256' => 'ZNEUscWwJu03bRinDYd0BAuwiWGG3oDocehVMwX2oVo',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'PEM'.DIRECTORY_SEPARATOR.'16k-rsa-example-cert.pem',
                [
                    'kty'     => 'RSA',
                    'n'       => 'tS3aeWW_wzlyXsDNFeBONFNq7W4lNWDjOUseNxx-R9AsqNJEWZFzaTtBI4Cam9Wf_2AlfP6i3RRpK76ooZObKwJmm1ReGcP7gf7JnODQv0W-m9x85a_fwHiI86Dhfy1YNh2zg1DO1kL_Q-sqKMOZ4g6uUfXGXjS5968sKCua3o-GEr-7GM6uw8zgpDmURtpupAFj3X1qCg6cjblPzMzcXdjACP4_zJpLc-sWpqY7pdLa26J5dgFGpTKWS7Xs96AlCPDz4uTRRFKDZarMFtzpjhWhNZyDGuYFFxNL4ca1tm-r4JyL-XuK9BTXC1WNXpqutzHNOj-tO9nCtRX02ZS3hmm1A9xndTZpfQ7lPuSA_kZEohkjcGyxtS-nup9khyMKGwvhg0MJS43VOuYSV6msk_z4dZ3-MCXVlJMTxLqWOSGHxHG0vDJQI5_IXCwkQLrVQIbt_X1ZylUdkmnKm4VuCBt4AHqK1F1jWpNXLYcFY-QW43c2Iln7v1uQFm_82CFHTanrNMBYNax2egYpSXpPS0naF6O1Y8bMPjPBU1jaoBAlfiSjCmHx5MOTg-PU9m1OnnR4XnOdDR0W8rUSS_iYz4Ucivou_7_XCTVlfuieAXT069ibXpGkTE58AgI6piVVYtaxyoADb3zr0a11Br0kS3gKRqxTq5GtgWTpz75VrFxXk8ATfwZF4PcOVX9fkUQStBKY9OGRryswLJbQ0lnz5ZR8QAAw1D2cAoWYoxUol5upjsrYrsGc7Ol3NhPPtoE0Vnxg49xQSZ0hhjhryId07aZ3QBr3NQ0XBoGhSNvO-M7ZyzDTNSUQusS5WyZsZputw_12E5y55_bbMPpKYbnx0aG93wmcna49jXoo5ZUMoJ_BQLaavGC0u-JTLT_subk5tKh3oVgDRevHwYeK1U4L4cdzpOzG8JVpcHyclofESk25DnHiQ92BfB1DR-6YadfQ8a4BXrIFlktDho1EmhXwWdT-dhO4ERPwf2Cx04iP3OdYCU_TNr3gVdB3fQLPkhV1K_od8zWrX7oqCGLkYCP_GUvl84dJoMequlyIO9IHtVpVHzGl-E48JoOHN00ULnoHzWzxUeGtda4twn9NQ-ptEjy9u0_8R-y2UqnC632wEmHpHzFqrOSYixp4GO_zAh-gmIhPJHuoH97vdcDRjGGFPO7kmMI0tBmxkt03ahYIqJKbPynHVLhsTuU7TVYrgTX6JkCR_IbudQTqVdz8oYO6tNqVrU89JI94_5ndJX1Wjmf1LPa8c31IQovBB0e-MlZ-rBkyTEttNuI8xC__OycsLhjAFx_bm0Qf2jfg2IJdLmDjGFHv3RlEdlRmJSyLY_lqKV4GAhjiEIEmduAKbygg2Jqhb6NKzHr1vxhRcWasnuhgTOunlGs3vezu9xz_4CvEKRMT6viU3tzqmGpT3zE7d0w9zMwn2eUlX0j7pKIiznrbkW2Dfe63f9X9bKYAsO5pcqcfAHqVaHl0iFXy5QoFwwjSuWwxKyhaY3tfY2rufLXCOzQ_G7BDoMRns8x6nCR-64Xuvp-EvBw0S790J_u9Z2W98rrW6c1cfn4cb9BRy3Rj64kWqlAUTRu6-qrX2RN5ywhoKfiJDH3m2q_MtgDlR3ke-5KuxaZwfM0hrcCppU5THbOwMe3XoDX-ZjD-3q-ikM8ueu4uTqDjtQrTQioFIxa-3prbNTsxBERQFZwlJtz2GmNHEAjgU-OwkMDObYAGc-ZAZritXe9vGtGFpdowMZ5k0FTUKSIsecPxn-nZlG-_qML8S63NXlU0RdbtYaLwQteFuXl_acAvuxOOnB3nZppJyIStP0uOPGhRowXSlThn0yFDht65TLly171JVrf4oFBDO4Q6EIJ7JMbRXCaEWJmeSNe_k71c3u4elbZ-C2i5JaO6bctZzO-xZ-CP7raQzHXMlpChYXqmpDU5bK2ySAbcDJDvg5WeRmQsqRxsFnI1EK1Jj_BKHZqOPz_q2SYyv69zPTsp5_w9z9YWCbOKP1KHyf9i9n6P5G3QkCzvlTDAbjR6nrrrnva0PZ0SjO4MzDOsIAa9S6vwRnWyE23vVI5RCv-IkLZ075LRkXKcj2EVPrDI3Mb1pUtfGu1H1M7m6V0SOTnaCwimIz3Ju2mwgnR-2lAAJKMd3vUaN1NfbEDuhZoMZfDrWzqOqA8Z2oyv6jHhby3DknbW4pn8tcaPCvScn1wotOeNFDvAfOIxikGEjUuXj-_gV2_dcFVIANseYpdhAS1tJjVX9JBwWcjbHnShy_9Y4f1zzrSwv4UbG7xDEGS1VaDUk5UwTTeeKQKzCkd6nYXxZYRMYDD_DcuGiCG9YvWm9hry1DkfdyCx5Pe8j8KMGUuEtIwLOIfmJDiCmE9fRAY85f9TAXyxkM-P1S_TcScKeSYrxLubX1DTuOGNDFKB4xNf0vi-lCFgLmx8tOr-RY7qtzrwrfcf7Kbpop-B5KpA2PhmoRTtZl4kF7RDeh-ZnUqcfyQcCIv_HewiMOmJ6iQDDjOWbsM8uEhl3ab-FzDYGAeT5bJs4EJAwEhsk28sXqnGzwJDUxw4mdLCYhiuI0ZwGOBUIzXQ-KHaH88PwYuQGLwM-s9uCKqJyO84I6XPe6bnqsL9NWmPhpvFxEZ7MvFCC2Z7nuGswQKpL92_QOS0NibZwzxBDUY7Qm3WsHxFzYm73JenQJGKzZPPLtjhIar7af2qb8KINgWGfIvrxR38osLT0Vg29M0DuMc',
                    'e'       => 'AQAB',
                    'x5t'     => 'XC_s0q4lqNalTFU6tNWR_Szk5dk',
                    'x5t#256' => '3nz2wIAoSbfVCmvy9k18bCPyIXacd3YfHrGq-qg3DVY',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'PEM'.DIRECTORY_SEPARATOR.'32k-rsa-example-cert.pem',
                [
                    'kty'     => 'RSA',
                    'n'       => 'qzPFsFIf3cSes25DloV3y3d8gKMcZVE_EQ_6e_MZnyqDbuOEP39yQs3aunzbZRoO8Xw8lLoJNduiKKsco7odI753kBvz1eLyke-sWBVZttbnYyz9AE3ZXfAb9rHW2AxgIqHNsQOsLJS_douGZwxawNdE90WM4QG80bDpkxxHfObtmZIbZoOFSeokDHA5jokQGzJ65t6ARtQOIht84pIlAr8RO0vCUiJ0R4TdAffbdIukMcVfSoZBlZJ_q-yBtPoqB1Nmr1x1FqCtR81NrEtdp7CUHy4yLIskMzHTwJL24dx8zPS9RBIAuR6HO6soQwQgKY5NYmyaZGuWDrzw0Lor9_jjcx3x7NlXEUffGyUdT_bZ6owsgd-SpvnbqXPXIf-u5JH7afSUuajytHnGVilQOpEg06B0F-AumUEx8vdLPczCx0CED11mhRhT1eRQPJlzxgqA22SN1Yz0P55R8QbfFYcflpEtZbHmdvwMSipEoEUyI8aA9z268oNVnnAGhG3cOqk8-4HOvtqZ9LIc8jUcQLtWX-PJav9EePnWuV6pFwzvKcwl09m08xIfIh9DvFVJz3Fks-X6c1tVo2Valftlj8fnlzu9WgownkwhM4KN2UpcHcff4G-v9zckhcpROSzZ1ax5mPOUMF6B2OVawMhf3li9A9JEpBDxVu2-gZU6NbhvfH1f4PdNPUnlasPylHn4qz4S6_V1fuxho-2O_V72w3V5FDBi-m2D9vDVQvJtuoiJxUEyOWaxsenuzoFlq3jNHwm0SiabwVjaMyre4qktmHopLuLX2ixME3rbTtaXLAaly-t2X6oS4nFyhwP9f_WbJb4Yh_RDxksPj1hR_4nH43NTYjZBlLDM0YRb4xRzFmATQOUhPou6LSUbl8Tl2z7WYFzlcKgHwkWRaTGUV8Sz_h-_IfgZDvCtyyLhzvWOmfJBhsV1nTbDrr8DivZGH5huBNH88v_gbCVw36aAjH8BnmcHQ0ImUUwXoiB1iWSWB3x1xdYnAyQf5RV2PK86wVc4EBRxW6MeJHWZr-kFgHtcwk2ys8MewL8xlKs1S64APAWtD-WsLGEnUVMfM5EuWjoS9kB4BI4DC6M0uyDjaCuFu80wMmWfx9C3-Y2x7l5Lw0G4gRcUk-F3ONtKfsxMqAmV6aUVkXmdkX5LLa105CpIVqflM40CPl5mlVGEFlTf9u0zclyQ0_-qWt78ZzkpolPj9XKHikdYA_DKbvtfgtgNC07GIwBctoQsOrKGOxigeWzrAwfS9S5Wt7hvcs2R0Y04rXoeSTPbHWLumsJYLxC2HPtam3IxQJzCljIOFB5Sqi9WLO5l_yjmUGS2Fzy5DkuyFuC3o79rB-Vu0zpHQ5sHdbyYkfvi3QZx4jLuj2ki-3_1Qj7RfVdd1yWeudnFUy5QGfWh3-VoaK9UIZ1EeX62owXTGNOJovn9yMdwbXmy75qrkPXadFQG3lnuqq_Ucd8ZAYJvwfQb6uhTSv1kSFCpxyyaSBYjLU44QDF6FRh_QHLMBM2DVasOT0hsF2UWsIXUneoJHk_qVZSRmj5EDaIrWAUEZfL_geiwcW3_L3Y9iaHMkB93fHNsVEpLmTO-vLHZHYN0c-kKNVBw_40xGZ5ZgPJlT4JZVvBKuB2ka2OsSLcRXZvzZZZTnrRHb_9dngGkFpI0gc6gFu2d1mPIIFp6JS7AJ4_sYKE4yxuGG7IsA4ErnNBEK9Sr1XSu0_KfcIv63dm_AybDg1vmqMLCl5EiP9OIFsWdIM42970PH9h8Ri7KUn0D53RSRVkV38NW312A2JYCHfEfbIxyibEIrsusib98x6Bedh-3BpsWyih2XlDT6AFwJdD0cc_Uf56Vqv9waUtsSx-1xBwliZ35MKq-IfV6hcLnFgLhxsqakV8aFLAEzI8Ulned6zjRAC28aaDOZcFdKEMD0wHPUW8-9UTQxAgug8otEITWSkKubyXbdofpVa9Xwjq1-jLb4eylqey0RokKrHO6B7F3KtUF8Zsm0mGEg7nvUhjEBFL3AqkLke5Nb_78uqb3tzZF3iO6ghENar9s1DUIYqNkbMSeh7smgER_PBUB0MGMqRnx8qcr5t5yBEurZ7qq7-LYoJOoc6UwaPrQN_AFRou4ugiRrxIrvOwrDPr4y2zoi9XKnBBuYMnt2AkGVCNIA0WOKgmex4x_2Nri2JlRieAPwNPfW5PLkyPVRfw0dNzhg7csMl1Wctdw1JpHJhgMswuhYhRWGyzYWE4ZU8lvQWqA42MOKfUixAV4LmEzGz2eRQSPGWjLC85-mcxf_vssmD-mbuJAjzlLDzzwllrTDCQrt18DftpAAHhD5hG2HmQH9RDzcS3sniIx4p2zyqBHVQsWM74BlQjbODjgHRHerTgxYaNmh4KRA38lmb9omrUhI2Q0Lj5CF2of_Apd7fo8u6LpBpdEtirkn_7-9vPPiGerClV6lSjoNi_I_hHCneAq-3KZq7hM5XliJPvUrws_m0X5n6_fazdk-gOohEuF0Aq_1I5633sS-DGrFyan2K7oeoBGQN994-kweTR0lLko14nC5wnvizbsv7sDUNJTjM7LMYIrhKEILTjjGQ6WuCkYhQuM4RAnx74jFIchW8pS1tEnUcIOyBWgFB9M2zdbNmJg7vH43mmX408jMYVKs9CQz2Y7Vu33S0dSp9sWxM1KUREFVy1xTbVgKNxLxOzXiLOjm_b4EifAHZh_KTf0POm5RESU-TSrO29y5puTHL-PLuOE30jrxXaKhW5UzmQLUMhBGI7geYP6fE6QxyUi0gD_tLdMmzxTlZiOXkE6HnBQ-3Ar54uA-RFUhnzU-XT3wm--eINsvqyrHCyLQlmM71aBXnMlH5g0NJjdm42XSecTopWfFCfcNe1-ufpUuMGGg0C3LxVN5fkTmB2_6gai0AHh4dNhefGkKCZ5OcSNtA_UUI1nKr_wgPTI4X1catN9RE9mMYhOt-I5gOVRCihxDcUcBl2apUaFK-jHPs5rABqhykbi_dOS-zy42I86Vcu4B-_0GNlRIPRLZWFIhNRy_kfCOq4kb4SK9DjTvHsaq6YWMoL9Jk3JiqvH4yrMZ6T-XEFdJ8DGSc41lo1YJwhFUu0eGbGFKxyUBrHv1l9ByPrqWaiepnBBsda4y8G3SoiCfndwkbvLeE5ykYgurPpkYX_bau2PqsoAkiJ_GmbitKpXD71C5PmzvzLvpxkgC6hQq-v4L4WLelADvBpeikX9k23qhR5H3mkzNeMZgHyoFisy161cDgOlcg64g6C2UzJKlb5C1tOlQwM3fdm7cjBJXOjuxgi8Ewx6ov90eeaqIEfFvnUu1_IC_tFve9P_Us21Ak53vwStlHueYHtedJsHg84C5Ppt_z1LFR3Hh8m1pOnlb3kJw5eGpvsXweZrIIN0cvwz-NZ_orIxjPxLf23wy-y-lhObK17BfX1g-p759XtRSaG4Rj_QedauXHAA-SKgvwAOY3kBuWo9Oxx73JbC1kov55TkecHj2lXO_o49O5LCOa_h0nHIVb3JIGWot11sF_6zwNzFM2WtHFNu7Iu9hllumC8rvz3HEbylvSPQYzBQKy8NSyC6T9wbH6cAYY-vl59q1J4DwBH3DHKoMAec8InlnBO_ekJa8SMdQMZxov0BaxJc0W__29w2Sza0cBsMslfpRIWRWMb4jNpyvCyEVxrGf7AakOl0_9P3JCQ2o8cuf-BGg_z_iQ3aTMYVWi_pWuxnhh5NchjQU8C3dxvnEd0Te9mmDlvZh-N9GULo0tlzHz3WZniUp7mxVQ3nkeS31M0LIIF3SetSMjXrGJ_4bzAnb3EjH44eFuvgOiJ8ChXLCmHLtIpFa0WSC6YVpBxqfPrxke-DyB2Lvz_46MSQ4iKvCFhdYWxBtwXCZDN5Dt4XFpMknL_VnuVU8a5_rRqpEebv_VF1pBZsvfTK6UXFWAApFvL4ebApuLsFInG3uk89N2SbenTTiBGWZWZjsEFsvf3iSFZdQ2bgKSLmJIsuXV1mUPkzGEr8SsPLDKhGNZBevtka-CfnukEPn7a3K_O5sYcccEtYwx0VNiC6dWu7B_-pflffa1m4pbhdg6KfykDO9_jU_LE692dhWUzbv977zGUlOnmsEMeqmSTo9V5Hv0UsEDGEjoe9piKidoZ8JdAq1WIpSBfW9M2wtkZHbi2nlaBnKJuTaaNs_nWjbG4y73hEqEqRlQMKrLsJU7rsmy3h6x6-J_tXfkKpWu_Z_PhR-ca2RV4ldwUNejBhBomg-6bcSq1lHXGTpwc0wSDmIUfE2W6ZZysaFpmGpTDFjTDqfeeAwwbzShK7Uc-OnJVNiQ5w1KALJNjXURSfI61vyWRBMtFHaC7t6ixwDfv6pqEa0xeDe4xf4Z1qdX1Zfs4xpdAyzZWmslUsXIYDtiTXq6NYGjnCEPYqneVGOWhP6re0UfzeqqB6p6_L42UoqFrrjU7jnEWRlz6gxdU9qOJgLX3u6CIYtN6b44tpsqA23fNBiuf4SqoYimbd2YVjXFRFFNZ2XqJ-wBqYcD5xIfudMN6W5cAD4p5cTQ11_-EqIp8rDxiWOs-PN8SQTIE7ZYQ6na-lSITpchNybreE9SqhzluoY71DN8oQuUJHonrAW5Hh_VroGBxpbO9XdNhw0XrC-S9iH9DDEUedanM2DznPUZsHHutG8H0K9AEyWRS01sAwrF73ZG57qy5IciYMHZuFbkY0lzwbF-vd15jgNfP4JTmZD2sVWwVgI7Qp9T2hd0uuZL_huHl2baRCyC_DSI9c6p3q9Ud_tBN_yCcNcUVx0rS6EGfzM8VYOGwyiBVBAgVDjBXiKBsUVWA3ljfOtYhLKBDHkqhvoQaczSI2fKX7L7cwgXeBdckoaNhno6mCpZBamuyBZ1Iy6TnguQi59MCCKdiczIpfeumbSDEovy2IbQmPqld_JI6WOufgldiITu3hXR5KNazan2mc3NrKu1SEXZpdzb4wJZZ26U_1xE2GLMJru05yZoVNEkN72DhagM1R5oqHwPzRcn3ahdYvUzDoP6UHEpa76A23lqafY7F98l66hmAnXXlEKzEVwthYoxWANYtVsxs9NktNJdNMB3OCMnCo9BWkefmjlrzMJSkBP_1mfxN2o3W1tMNXpk5OQPO20_eWPF3iYhobSo8fcxzXtw9bg1BXr0TADj0hl_z4jw93wVGGLlsA3qYstay0I9yJgHBZmhxc7V1JzNWdwxIDmRgA5eCm1ELVBxpIup9WGZlUs1rzwqXzI-37i7l3dwFfCf_i2g8m-gNQjuM6YqkSz-XKcn-sJEg1XSMhoB15sgYE9U-2Oe-_EGLK0dOU2zyHO40F8ghvhKWpuAcITX_QnEMremwsiCl0PEnGZ98BXzlRvd1MFNc0ZUwzN-wTVxs4jNkteNbp0MjIKA5Y6FiCEX6koNWY9cLXSNg4XG4IsWRQrfIn2WWFz_nhzlaZNm_NUM1kmKRREPmsvQ',
                    'e'       => 'AQAB',
                    'x5t'     => 'KGApLybHWJmBwZGgBk07AlRD9nU',
                    'x5t#256' => 'YD12k6kc4xuh_5vEHMyyOFpGs6VqTyaKMlxg0Nt2crA',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'DER'.DIRECTORY_SEPARATOR.'512b-rsa-example-cert.der',
                [
                    'kty'     => 'RSA',
                    'n'       => 'm_xmkHmEQrurE_0re_jeFRLl8ZPjBop7uLHhnia7lQG_5zDtZIUC3RVpqDSwBuw_NTweGyuP-o8AG98HxqxTBw',
                    'e'       => 'AQAB',
                    'x5t'     => 'Bxy5TwzIUU0CQSRwjuiyaHvX2dU',
                    'x5t#256' => 'Xw-1FmWBquZKEBwVg7G-vnToFKkeeooUuh6DXXj26ec',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'DER'.DIRECTORY_SEPARATOR.'1024b-rsa-example-cert.der',
                [
                    'kty'     => 'RSA',
                    'n'       => 'xgEGvHk-U_RY0j9l3MP7o-S2a6uf4XaRBhu1ztdCHz8tMG8Kj4_qJmgsSZQD17sRctHGBTUJWp4CLtBwCf0zAGVzySwUkcHSu1_2mZ_w7Nr0TQHKeWr_j8pvXH534DKEvugr21DAHbi4c654eLUL-JW_wJJYqJh7qHM3W3Fh7ys',
                    'e'       => 'AQAB',
                    'x5t'     => '4bK45ewZ00Wk-a_shpTw2cCqJc8',
                    'x5t#256' => '5F5GTPOxBGAOsVyuYzqUBjri0R2YDTiDowiQbs6oGgU',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'DER'.DIRECTORY_SEPARATOR.'2048b-rsa-example-cert.der',
                [
                    'kty'     => 'RSA',
                    'n'       => 'tM_RXjMp7AvPrnb1_i3ImcZ4ebkY-AvUurTXngJSBgn0GJNM1HDRQqApE5JzUHf2BImsAyzW8QarrWzA2dWmq8rNWtJWJlHlSwiKr8wZDyU0kLAqKUEPVfFrk9uds8zc7OvHVRjXQiXeSTUUMpKcHsZp4zz79Jr4-4vF4Bt-_U8luj_llleaJHlJFyfXiUtqLg2HUdkjPQaFVvhYMQ7ugZl4aM1uRH7J2oxaexy_JEApSNEDnO_cripd-Pdqx-m8xbBZ9pX8FsvYnO3D_BKQk3hadbRWg_r8QYT2ZHk0NRyseoUOc3hyAeckiSWe2n9lvK-HkxmM23UVtuAwxwj4WQ',
                    'e'       => 'AQAB',
                    'x5t'     => 'y17eUFeZUYeOLmcTxTvpOOsjfkA',
                    'x5t#256' => 'B4plbjZwSZyZG7AnRoIFive9wF_EYsYF8PiVgXmBbNc',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'DER'.DIRECTORY_SEPARATOR.'4096b-rsa-example-cert.der',
                [
                    'kty'     => 'RSA',
                    'n'       => 'sL1iEzi3sk20tUP1GnKniCyCtelBy70spiJW24k-5qQ-EjMAd-N8aSJVzeuHwtGNcpU-iy3l-ErewHCaxiFdwDJiXLA7Dc4KOe-y6rTb5zpCx9BqI4rBRCkIkRF-oDoKvbVkqsGhDXHExLAF7legENUk_hterNNIjfdoY1_Vf1eurJ0cE7Cf6eFkaS0nQI-Nu9oYjNfaiIPc64fdntq0MuxP1EoVuIKTq4YNn-n3AgZvmlyIGvqsWki3IXA1Lz166SMU3fzlkNt0IbyBM5Bmz5QQPCezcPSgsmsW2DARW9YtJQY8Ci45nKIoYiOz1bYQDrvwe9Q9oSnBYyqX7-A9VGpv9FbpisIcLoWVTYy6tQUdRSkSdQoqCxuMAk69C1YLb71MoRa0vtz3VEdE-R5QEFjzMkAx4AqWzh1tMHNIW7jXjv5UvNi44nhjRcSpjARRfZbDds7AOkMN9l5G9vxBZbVwrabjsFc7XZODA652g18vczGbqhR6b-ZVk2w1cA3chEDXJWJWwBGw3rxEKP6wDmRZfeDLut6wIC4j3mTeCHUv-PKK-SmkGgjntA7gG-BljSEONnGEOU7BB1rfhSDgDEqX_YTT4w3rtbn3-NAzrbIshnl_TVYqirbbWh6b3e629s7GrG3ABlJfnzUCY-KiJj0gfU4amaj07pBHDPzbW3k',
                    'e'       => 'AQAB',
                    'x5t'     => 'IBO6381r3QWOObmNaxF36HBgO5M',
                    'x5t#256' => 'yVWIatQnBpbU9lUGZmRlGg2bldGtJPpqQXfq3LhBq3M',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'DER'.DIRECTORY_SEPARATOR.'8192b-rsa-example-cert.der',
                [
                    'kty'     => 'RSA',
                    'n'       => 'q5lcEwG8rUflI1aL6omAaF5R1DFkCMllFaQ3HUwlwCWYNNyKxF1G2e-P3Y6SFWyp0sFfmDcvuebOY_Dw3KlC756bQUMEXH6TaubYDcXaKDyrdKgCSoufjhwHkNpRz3VxpkLADJQIHdijes2JN3daGARxSJLcjoSaZvq_LBCIHTTDGESBXJP6RtbjAjGjuLUgmcvkl029Xl8ylkrcibjTzXmOod3vioTnX5aZNT1c7evmskvixWG1NlHOhZ1HdXiPHLjKxnr4lHl9lxtTjkNSsF-Nz0bYHCpWZ9u98nkgvFAxNUmiwX5nHIqo39AK8YVuVmDGYzY-dPtD1UtCBXgj-Ryq1cPU66H7kEfvbn1kZRF0XcxqIUVDlpa_h4Aq7r8KnQ6nVF59oM8AwsrRu3llvlRzNCaRUhafZ6YUHR19j_6GpAJtOWwwV5m2qKs9EhfL9Kvz9DqWh3DBt0CuGIDS0NuBAt2_RmNQBP1u7L8pYZ_9kV-Y7YM9ocbuYpUbTy4vio33Pl2wG8iozgPIgOcbne4Vh4TGpe0hbXaL-a_84CVOWX4JyLxyBEWGB6PLfH74NyXyvh57X6Cn3P0Xr2rSgPEgEEovw5i9qDeqqzeO-GvUouhQjZgURP5USjd120IPjVoZP8RPRCAPUBQSUmi2dyHANRI3ydIhTKOEdZCVvIlVNu33wfN55kEeLCXBiDvfvozUbCGuuOkbs5Yz7vE8K9xlU_Xo2icptY_u3XMPW6YKRP6lvGtovn9295vENHOJDFCVkcJ819vHVqJnoiGAf_QX0J74NLm6fnWboH6-5BcIDl18uB3qEFAlneRflIrC2XBZju-dTuTaHy14WvVJNjTMUBgVQ4gaS1X2wmAztwv-Rk8o6k-KJuSZDWVEZyH3NaddkYSVONOMzIuuClbg4cEgLP2cxxqz8JdnyT2NNfMdGfxP4Nd_RvPtTD9kTVewlurzYVjoi8CC6VhV2Tgcp-UvT6Z0Yne-65dXi31VRqQWG8adWQ3gc9NP1oXfJqVt26ldXF9AVf7PcFcm7xzr2mwZKY-DMk1m1hBvUGeg7Iab34OABOY6J4AxXiXqKx3JV24SFydaSSevsulSrmUJU3g8TR-WwTh06Yp8DZplCU9MEvfyUSShtHED72anVRgVe8jw47k9TavJ-hPiAq0HUmmKGUeKvrqWN4bMpSiMCmHTkcqS_d4Dn4ZAI8W0DIluc9sXBaiUUSIt6t7gGNOZGUyZ-ZN4GNxVlMazB6CieGRhoPfRmXw7wq0k2R5BU1Q8PSj8jrZ88DgdfENnWCGy6Aq450OwfufGaHZDwAUD1kUoRGBkzIxvkWLVdQtmP4iZXOLSany0RtPZLGjSH-x0vQ',
                    'e'       => 'AQAB',
                    'x5t'     => 'YV6dSQ9sNS7rhNWcj-M4XuMmOE4',
                    'x5t#256' => 'ZNEUscWwJu03bRinDYd0BAuwiWGG3oDocehVMwX2oVo',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'DER'.DIRECTORY_SEPARATOR.'16k-rsa-example-cert.der',
                [
                    'kty'     => 'RSA',
                    'n'       => 'tS3aeWW_wzlyXsDNFeBONFNq7W4lNWDjOUseNxx-R9AsqNJEWZFzaTtBI4Cam9Wf_2AlfP6i3RRpK76ooZObKwJmm1ReGcP7gf7JnODQv0W-m9x85a_fwHiI86Dhfy1YNh2zg1DO1kL_Q-sqKMOZ4g6uUfXGXjS5968sKCua3o-GEr-7GM6uw8zgpDmURtpupAFj3X1qCg6cjblPzMzcXdjACP4_zJpLc-sWpqY7pdLa26J5dgFGpTKWS7Xs96AlCPDz4uTRRFKDZarMFtzpjhWhNZyDGuYFFxNL4ca1tm-r4JyL-XuK9BTXC1WNXpqutzHNOj-tO9nCtRX02ZS3hmm1A9xndTZpfQ7lPuSA_kZEohkjcGyxtS-nup9khyMKGwvhg0MJS43VOuYSV6msk_z4dZ3-MCXVlJMTxLqWOSGHxHG0vDJQI5_IXCwkQLrVQIbt_X1ZylUdkmnKm4VuCBt4AHqK1F1jWpNXLYcFY-QW43c2Iln7v1uQFm_82CFHTanrNMBYNax2egYpSXpPS0naF6O1Y8bMPjPBU1jaoBAlfiSjCmHx5MOTg-PU9m1OnnR4XnOdDR0W8rUSS_iYz4Ucivou_7_XCTVlfuieAXT069ibXpGkTE58AgI6piVVYtaxyoADb3zr0a11Br0kS3gKRqxTq5GtgWTpz75VrFxXk8ATfwZF4PcOVX9fkUQStBKY9OGRryswLJbQ0lnz5ZR8QAAw1D2cAoWYoxUol5upjsrYrsGc7Ol3NhPPtoE0Vnxg49xQSZ0hhjhryId07aZ3QBr3NQ0XBoGhSNvO-M7ZyzDTNSUQusS5WyZsZputw_12E5y55_bbMPpKYbnx0aG93wmcna49jXoo5ZUMoJ_BQLaavGC0u-JTLT_subk5tKh3oVgDRevHwYeK1U4L4cdzpOzG8JVpcHyclofESk25DnHiQ92BfB1DR-6YadfQ8a4BXrIFlktDho1EmhXwWdT-dhO4ERPwf2Cx04iP3OdYCU_TNr3gVdB3fQLPkhV1K_od8zWrX7oqCGLkYCP_GUvl84dJoMequlyIO9IHtVpVHzGl-E48JoOHN00ULnoHzWzxUeGtda4twn9NQ-ptEjy9u0_8R-y2UqnC632wEmHpHzFqrOSYixp4GO_zAh-gmIhPJHuoH97vdcDRjGGFPO7kmMI0tBmxkt03ahYIqJKbPynHVLhsTuU7TVYrgTX6JkCR_IbudQTqVdz8oYO6tNqVrU89JI94_5ndJX1Wjmf1LPa8c31IQovBB0e-MlZ-rBkyTEttNuI8xC__OycsLhjAFx_bm0Qf2jfg2IJdLmDjGFHv3RlEdlRmJSyLY_lqKV4GAhjiEIEmduAKbygg2Jqhb6NKzHr1vxhRcWasnuhgTOunlGs3vezu9xz_4CvEKRMT6viU3tzqmGpT3zE7d0w9zMwn2eUlX0j7pKIiznrbkW2Dfe63f9X9bKYAsO5pcqcfAHqVaHl0iFXy5QoFwwjSuWwxKyhaY3tfY2rufLXCOzQ_G7BDoMRns8x6nCR-64Xuvp-EvBw0S790J_u9Z2W98rrW6c1cfn4cb9BRy3Rj64kWqlAUTRu6-qrX2RN5ywhoKfiJDH3m2q_MtgDlR3ke-5KuxaZwfM0hrcCppU5THbOwMe3XoDX-ZjD-3q-ikM8ueu4uTqDjtQrTQioFIxa-3prbNTsxBERQFZwlJtz2GmNHEAjgU-OwkMDObYAGc-ZAZritXe9vGtGFpdowMZ5k0FTUKSIsecPxn-nZlG-_qML8S63NXlU0RdbtYaLwQteFuXl_acAvuxOOnB3nZppJyIStP0uOPGhRowXSlThn0yFDht65TLly171JVrf4oFBDO4Q6EIJ7JMbRXCaEWJmeSNe_k71c3u4elbZ-C2i5JaO6bctZzO-xZ-CP7raQzHXMlpChYXqmpDU5bK2ySAbcDJDvg5WeRmQsqRxsFnI1EK1Jj_BKHZqOPz_q2SYyv69zPTsp5_w9z9YWCbOKP1KHyf9i9n6P5G3QkCzvlTDAbjR6nrrrnva0PZ0SjO4MzDOsIAa9S6vwRnWyE23vVI5RCv-IkLZ075LRkXKcj2EVPrDI3Mb1pUtfGu1H1M7m6V0SOTnaCwimIz3Ju2mwgnR-2lAAJKMd3vUaN1NfbEDuhZoMZfDrWzqOqA8Z2oyv6jHhby3DknbW4pn8tcaPCvScn1wotOeNFDvAfOIxikGEjUuXj-_gV2_dcFVIANseYpdhAS1tJjVX9JBwWcjbHnShy_9Y4f1zzrSwv4UbG7xDEGS1VaDUk5UwTTeeKQKzCkd6nYXxZYRMYDD_DcuGiCG9YvWm9hry1DkfdyCx5Pe8j8KMGUuEtIwLOIfmJDiCmE9fRAY85f9TAXyxkM-P1S_TcScKeSYrxLubX1DTuOGNDFKB4xNf0vi-lCFgLmx8tOr-RY7qtzrwrfcf7Kbpop-B5KpA2PhmoRTtZl4kF7RDeh-ZnUqcfyQcCIv_HewiMOmJ6iQDDjOWbsM8uEhl3ab-FzDYGAeT5bJs4EJAwEhsk28sXqnGzwJDUxw4mdLCYhiuI0ZwGOBUIzXQ-KHaH88PwYuQGLwM-s9uCKqJyO84I6XPe6bnqsL9NWmPhpvFxEZ7MvFCC2Z7nuGswQKpL92_QOS0NibZwzxBDUY7Qm3WsHxFzYm73JenQJGKzZPPLtjhIar7af2qb8KINgWGfIvrxR38osLT0Vg29M0DuMc',
                    'e'       => 'AQAB',
                    'x5t'     => 'XC_s0q4lqNalTFU6tNWR_Szk5dk',
                    'x5t#256' => '3nz2wIAoSbfVCmvy9k18bCPyIXacd3YfHrGq-qg3DVY',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'RSA'.DIRECTORY_SEPARATOR.'DER'.DIRECTORY_SEPARATOR.'32k-rsa-example-cert.der',
                [
                    'kty'     => 'RSA',
                    'n'       => 'qzPFsFIf3cSes25DloV3y3d8gKMcZVE_EQ_6e_MZnyqDbuOEP39yQs3aunzbZRoO8Xw8lLoJNduiKKsco7odI753kBvz1eLyke-sWBVZttbnYyz9AE3ZXfAb9rHW2AxgIqHNsQOsLJS_douGZwxawNdE90WM4QG80bDpkxxHfObtmZIbZoOFSeokDHA5jokQGzJ65t6ARtQOIht84pIlAr8RO0vCUiJ0R4TdAffbdIukMcVfSoZBlZJ_q-yBtPoqB1Nmr1x1FqCtR81NrEtdp7CUHy4yLIskMzHTwJL24dx8zPS9RBIAuR6HO6soQwQgKY5NYmyaZGuWDrzw0Lor9_jjcx3x7NlXEUffGyUdT_bZ6owsgd-SpvnbqXPXIf-u5JH7afSUuajytHnGVilQOpEg06B0F-AumUEx8vdLPczCx0CED11mhRhT1eRQPJlzxgqA22SN1Yz0P55R8QbfFYcflpEtZbHmdvwMSipEoEUyI8aA9z268oNVnnAGhG3cOqk8-4HOvtqZ9LIc8jUcQLtWX-PJav9EePnWuV6pFwzvKcwl09m08xIfIh9DvFVJz3Fks-X6c1tVo2Valftlj8fnlzu9WgownkwhM4KN2UpcHcff4G-v9zckhcpROSzZ1ax5mPOUMF6B2OVawMhf3li9A9JEpBDxVu2-gZU6NbhvfH1f4PdNPUnlasPylHn4qz4S6_V1fuxho-2O_V72w3V5FDBi-m2D9vDVQvJtuoiJxUEyOWaxsenuzoFlq3jNHwm0SiabwVjaMyre4qktmHopLuLX2ixME3rbTtaXLAaly-t2X6oS4nFyhwP9f_WbJb4Yh_RDxksPj1hR_4nH43NTYjZBlLDM0YRb4xRzFmATQOUhPou6LSUbl8Tl2z7WYFzlcKgHwkWRaTGUV8Sz_h-_IfgZDvCtyyLhzvWOmfJBhsV1nTbDrr8DivZGH5huBNH88v_gbCVw36aAjH8BnmcHQ0ImUUwXoiB1iWSWB3x1xdYnAyQf5RV2PK86wVc4EBRxW6MeJHWZr-kFgHtcwk2ys8MewL8xlKs1S64APAWtD-WsLGEnUVMfM5EuWjoS9kB4BI4DC6M0uyDjaCuFu80wMmWfx9C3-Y2x7l5Lw0G4gRcUk-F3ONtKfsxMqAmV6aUVkXmdkX5LLa105CpIVqflM40CPl5mlVGEFlTf9u0zclyQ0_-qWt78ZzkpolPj9XKHikdYA_DKbvtfgtgNC07GIwBctoQsOrKGOxigeWzrAwfS9S5Wt7hvcs2R0Y04rXoeSTPbHWLumsJYLxC2HPtam3IxQJzCljIOFB5Sqi9WLO5l_yjmUGS2Fzy5DkuyFuC3o79rB-Vu0zpHQ5sHdbyYkfvi3QZx4jLuj2ki-3_1Qj7RfVdd1yWeudnFUy5QGfWh3-VoaK9UIZ1EeX62owXTGNOJovn9yMdwbXmy75qrkPXadFQG3lnuqq_Ucd8ZAYJvwfQb6uhTSv1kSFCpxyyaSBYjLU44QDF6FRh_QHLMBM2DVasOT0hsF2UWsIXUneoJHk_qVZSRmj5EDaIrWAUEZfL_geiwcW3_L3Y9iaHMkB93fHNsVEpLmTO-vLHZHYN0c-kKNVBw_40xGZ5ZgPJlT4JZVvBKuB2ka2OsSLcRXZvzZZZTnrRHb_9dngGkFpI0gc6gFu2d1mPIIFp6JS7AJ4_sYKE4yxuGG7IsA4ErnNBEK9Sr1XSu0_KfcIv63dm_AybDg1vmqMLCl5EiP9OIFsWdIM42970PH9h8Ri7KUn0D53RSRVkV38NW312A2JYCHfEfbIxyibEIrsusib98x6Bedh-3BpsWyih2XlDT6AFwJdD0cc_Uf56Vqv9waUtsSx-1xBwliZ35MKq-IfV6hcLnFgLhxsqakV8aFLAEzI8Ulned6zjRAC28aaDOZcFdKEMD0wHPUW8-9UTQxAgug8otEITWSkKubyXbdofpVa9Xwjq1-jLb4eylqey0RokKrHO6B7F3KtUF8Zsm0mGEg7nvUhjEBFL3AqkLke5Nb_78uqb3tzZF3iO6ghENar9s1DUIYqNkbMSeh7smgER_PBUB0MGMqRnx8qcr5t5yBEurZ7qq7-LYoJOoc6UwaPrQN_AFRou4ugiRrxIrvOwrDPr4y2zoi9XKnBBuYMnt2AkGVCNIA0WOKgmex4x_2Nri2JlRieAPwNPfW5PLkyPVRfw0dNzhg7csMl1Wctdw1JpHJhgMswuhYhRWGyzYWE4ZU8lvQWqA42MOKfUixAV4LmEzGz2eRQSPGWjLC85-mcxf_vssmD-mbuJAjzlLDzzwllrTDCQrt18DftpAAHhD5hG2HmQH9RDzcS3sniIx4p2zyqBHVQsWM74BlQjbODjgHRHerTgxYaNmh4KRA38lmb9omrUhI2Q0Lj5CF2of_Apd7fo8u6LpBpdEtirkn_7-9vPPiGerClV6lSjoNi_I_hHCneAq-3KZq7hM5XliJPvUrws_m0X5n6_fazdk-gOohEuF0Aq_1I5633sS-DGrFyan2K7oeoBGQN994-kweTR0lLko14nC5wnvizbsv7sDUNJTjM7LMYIrhKEILTjjGQ6WuCkYhQuM4RAnx74jFIchW8pS1tEnUcIOyBWgFB9M2zdbNmJg7vH43mmX408jMYVKs9CQz2Y7Vu33S0dSp9sWxM1KUREFVy1xTbVgKNxLxOzXiLOjm_b4EifAHZh_KTf0POm5RESU-TSrO29y5puTHL-PLuOE30jrxXaKhW5UzmQLUMhBGI7geYP6fE6QxyUi0gD_tLdMmzxTlZiOXkE6HnBQ-3Ar54uA-RFUhnzU-XT3wm--eINsvqyrHCyLQlmM71aBXnMlH5g0NJjdm42XSecTopWfFCfcNe1-ufpUuMGGg0C3LxVN5fkTmB2_6gai0AHh4dNhefGkKCZ5OcSNtA_UUI1nKr_wgPTI4X1catN9RE9mMYhOt-I5gOVRCihxDcUcBl2apUaFK-jHPs5rABqhykbi_dOS-zy42I86Vcu4B-_0GNlRIPRLZWFIhNRy_kfCOq4kb4SK9DjTvHsaq6YWMoL9Jk3JiqvH4yrMZ6T-XEFdJ8DGSc41lo1YJwhFUu0eGbGFKxyUBrHv1l9ByPrqWaiepnBBsda4y8G3SoiCfndwkbvLeE5ykYgurPpkYX_bau2PqsoAkiJ_GmbitKpXD71C5PmzvzLvpxkgC6hQq-v4L4WLelADvBpeikX9k23qhR5H3mkzNeMZgHyoFisy161cDgOlcg64g6C2UzJKlb5C1tOlQwM3fdm7cjBJXOjuxgi8Ewx6ov90eeaqIEfFvnUu1_IC_tFve9P_Us21Ak53vwStlHueYHtedJsHg84C5Ppt_z1LFR3Hh8m1pOnlb3kJw5eGpvsXweZrIIN0cvwz-NZ_orIxjPxLf23wy-y-lhObK17BfX1g-p759XtRSaG4Rj_QedauXHAA-SKgvwAOY3kBuWo9Oxx73JbC1kov55TkecHj2lXO_o49O5LCOa_h0nHIVb3JIGWot11sF_6zwNzFM2WtHFNu7Iu9hllumC8rvz3HEbylvSPQYzBQKy8NSyC6T9wbH6cAYY-vl59q1J4DwBH3DHKoMAec8InlnBO_ekJa8SMdQMZxov0BaxJc0W__29w2Sza0cBsMslfpRIWRWMb4jNpyvCyEVxrGf7AakOl0_9P3JCQ2o8cuf-BGg_z_iQ3aTMYVWi_pWuxnhh5NchjQU8C3dxvnEd0Te9mmDlvZh-N9GULo0tlzHz3WZniUp7mxVQ3nkeS31M0LIIF3SetSMjXrGJ_4bzAnb3EjH44eFuvgOiJ8ChXLCmHLtIpFa0WSC6YVpBxqfPrxke-DyB2Lvz_46MSQ4iKvCFhdYWxBtwXCZDN5Dt4XFpMknL_VnuVU8a5_rRqpEebv_VF1pBZsvfTK6UXFWAApFvL4ebApuLsFInG3uk89N2SbenTTiBGWZWZjsEFsvf3iSFZdQ2bgKSLmJIsuXV1mUPkzGEr8SsPLDKhGNZBevtka-CfnukEPn7a3K_O5sYcccEtYwx0VNiC6dWu7B_-pflffa1m4pbhdg6KfykDO9_jU_LE692dhWUzbv977zGUlOnmsEMeqmSTo9V5Hv0UsEDGEjoe9piKidoZ8JdAq1WIpSBfW9M2wtkZHbi2nlaBnKJuTaaNs_nWjbG4y73hEqEqRlQMKrLsJU7rsmy3h6x6-J_tXfkKpWu_Z_PhR-ca2RV4ldwUNejBhBomg-6bcSq1lHXGTpwc0wSDmIUfE2W6ZZysaFpmGpTDFjTDqfeeAwwbzShK7Uc-OnJVNiQ5w1KALJNjXURSfI61vyWRBMtFHaC7t6ixwDfv6pqEa0xeDe4xf4Z1qdX1Zfs4xpdAyzZWmslUsXIYDtiTXq6NYGjnCEPYqneVGOWhP6re0UfzeqqB6p6_L42UoqFrrjU7jnEWRlz6gxdU9qOJgLX3u6CIYtN6b44tpsqA23fNBiuf4SqoYimbd2YVjXFRFFNZ2XqJ-wBqYcD5xIfudMN6W5cAD4p5cTQ11_-EqIp8rDxiWOs-PN8SQTIE7ZYQ6na-lSITpchNybreE9SqhzluoY71DN8oQuUJHonrAW5Hh_VroGBxpbO9XdNhw0XrC-S9iH9DDEUedanM2DznPUZsHHutG8H0K9AEyWRS01sAwrF73ZG57qy5IciYMHZuFbkY0lzwbF-vd15jgNfP4JTmZD2sVWwVgI7Qp9T2hd0uuZL_huHl2baRCyC_DSI9c6p3q9Ud_tBN_yCcNcUVx0rS6EGfzM8VYOGwyiBVBAgVDjBXiKBsUVWA3ljfOtYhLKBDHkqhvoQaczSI2fKX7L7cwgXeBdckoaNhno6mCpZBamuyBZ1Iy6TnguQi59MCCKdiczIpfeumbSDEovy2IbQmPqld_JI6WOufgldiITu3hXR5KNazan2mc3NrKu1SEXZpdzb4wJZZ26U_1xE2GLMJru05yZoVNEkN72DhagM1R5oqHwPzRcn3ahdYvUzDoP6UHEpa76A23lqafY7F98l66hmAnXXlEKzEVwthYoxWANYtVsxs9NktNJdNMB3OCMnCo9BWkefmjlrzMJSkBP_1mfxN2o3W1tMNXpk5OQPO20_eWPF3iYhobSo8fcxzXtw9bg1BXr0TADj0hl_z4jw93wVGGLlsA3qYstay0I9yJgHBZmhxc7V1JzNWdwxIDmRgA5eCm1ELVBxpIup9WGZlUs1rzwqXzI-37i7l3dwFfCf_i2g8m-gNQjuM6YqkSz-XKcn-sJEg1XSMhoB15sgYE9U-2Oe-_EGLK0dOU2zyHO40F8ghvhKWpuAcITX_QnEMremwsiCl0PEnGZ98BXzlRvd1MFNc0ZUwzN-wTVxs4jNkteNbp0MjIKA5Y6FiCEX6koNWY9cLXSNg4XG4IsWRQrfIn2WWFz_nhzlaZNm_NUM1kmKRREPmsvQ',
                    'e'       => 'AQAB',
                    'x5t'     => 'KGApLybHWJmBwZGgBk07AlRD9nU',
                    'x5t#256' => 'YD12k6kc4xuh_5vEHMyyOFpGs6VqTyaKMlxg0Nt2crA',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'PEM'.DIRECTORY_SEPARATOR.'prime256v1-cert.pem',
                [
                    'kty'     => 'EC',
                    'crv'     => 'P-256',
                    'x'       => 'xEsr_55aqgFXdrbRNz1_WSNI8UaSUxCka2kGEN1bXsI',
                    'y'       => 'SM45Hsr9dnUR6Ox-TpmNv2fbDX4CoVo-3patMUpXANA',
                    'x5t'     => 'ZnnaQDssCKJQZLp6zyHssIZOa7o',
                    'x5t#256' => 'v7VlokKTGL3anRk8Nl0VcqVC9u5j2Fb5tdlQntUgDT4',
                ],
            ],
            [
                'file://'.__DIR__.DIRECTORY_SEPARATOR.'EC'.DIRECTORY_SEPARATOR.'DER'.DIRECTORY_SEPARATOR.'prime256v1-cert.der',
                [
                    'kty'     => 'EC',
                    'crv'     => 'P-256',
                    'x'       => 'xEsr_55aqgFXdrbRNz1_WSNI8UaSUxCka2kGEN1bXsI',
                    'y'       => 'SM45Hsr9dnUR6Ox-TpmNv2fbDX4CoVo-3patMUpXANA',
                    'x5t'     => 'ZnnaQDssCKJQZLp6zyHssIZOa7o',
                    'x5t#256' => 'v7VlokKTGL3anRk8Nl0VcqVC9u5j2Fb5tdlQntUgDT4',
                ],
            ],
        ];
    }
}
