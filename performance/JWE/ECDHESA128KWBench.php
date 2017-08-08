<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Performance\JWE;

use Jose\Component\Core\JWK;
use Jose\Performance\JWE\EncryptionBench;

/**
 * @Groups({"JWE", "ECDHESA128KW"})
 */
final class ECDHESA128KWBench extends EncryptionBench
{
    /**
     * @return array
     */
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A128CBC-HS256'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A192CBC-HS384'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A256CBC-HS512'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A128GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A192GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A128KW', 'enc' => 'A256GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    protected function getAAD(): ?string
    {
        return 'A,B,C,D';
    }

    /**
     * {@inheritdoc}
     */
    public function dataInputs(): array
    {
        return [
            [
                'input' => '{"ciphertext":"JBjNpqtmusVlk1bKDYQZPqUEMO8THMEnEtlq0ZpGCzbkBrZgzk4FZEVVwrvva_xHI0_2CPJric0Q8f2BblWiQORAavwzqQNaLISZUkRf2EgarCdO-mY0rr9JvmQIqtG8XV9GAkQWiVdbR_CFoZfrCV0gdSOI5UbXgy69AXpCsPfyFBKwZCbEkCsaZAMqY_sWuoPG1psffuSs7_RMwSPQAHfHd9h4uPg","iv":"WuveaDKiJReSIk5N","tag":"eHP86Mj3feO_ekbdln4KjQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBWkxFUXJVY0Q3NkZYVENZX0NaZXBUVGpGRDZQUUVURnNSdlgzNjRTUm9MZDBIb08yMGhvbG10Vzc5enAybTRxclRrTlRMdHA3UXJ5WEFWVmJPcks1blhOIiwieSI6IkFMQVo5LXFXSXJwdHRlSUkxeVFXN1VPcFlza0JHUENHZ2lia1loMWVSVG1weE5RNXFCVVdCNGVlZmhXeDVOanN1OHNDT2pESk5XTWhORXF1Uy1RNzhYRGgifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"BtSwz6FCdMt3CFrqDqDmVkVTvAxpoye_mtNPK5cd2mRckG3WAM6UNQ"}',
            ],[
                'input' => '{"ciphertext":"Blf6GKHXzJbouFa1WMZBCsB9I7Bt9z3wuFkG6VVLpPaPbw0NcAolDMEZxzLaS5mA1Va6gm6imlqqTOm3UM7VHiNqxaj3xWnn8aGpr52HJAb4-1Hav1vsIFmOFJUBRKrsYTaY88-Xat8M4zQ_cLGOn63dj4yxXA-2CYbPplHxSjKjbipvIQV7e6vgi7ctA-YXGEj12FHQXajYuqTZDHsy3bjsfF86FqwRBq7Lw0JrM_U","iv":"lKsundpHV5gV3nCQNcGnUg","tag":"auhFb_bmaZhIWeW4s07bHQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJPT3I5cV9Id0pqX1hvbTdHWGZPNWx3RmRxZVo4VV9xWjlfQ0JOLW1NUFhJIiwieSI6Ik93U09IZlhJQl9QYUxpSWxocTZpcUpRSW5nUkR3bkVrMllJTnFLaWtLaGMifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"iLBpHs28Z_L5Rqayg_ptYugXFmHbXwP8i0w8-OyY5mZ86ccLtP0rFQ"}',
            ],[
                'input' => '{"ciphertext":"LzVLq7rWty2Av4MPoyLwcR-ynL_Pd7Eana_Kbn2lSj6Sook3dKr3_dth5YTtYqlAsBbSgF9k5x2pJVyND2jK4oxBqcsLyUo0YPcXyDVKS5dePDQ8AOYrCxHCu43wbgo3btYDPSBcsMRAHBR4ieMtwHYLAF-9YFrdU-9OZkK_kwWiYQ-vj2IOIVw6w0nw9m9SDIH0q05tX_0orbHXNU7LFPdFRCdLmJFMKooO_qkyJsU","iv":"zZWqXLml5H1ZA4rB2Ts7Fw","tag":"7bUORhJpFVHXC9LE2rvLsYJ-wtwfsXJ6","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJUVzgtNEhCY0NoZlhyR2dKRFItMUpaN2pMaHdPd0lERUt2XzczcWNreWp3IiwieSI6Ijh4dlZBeThfWWQ5VjRIYVZVcTYyakhtWGMwMzJJLTJHNV83SWJKWjNoMmcifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"KZtomkB3pnFO78_jDedlBdLlXRp05mAxl6ESH2AMxMMq02OZLw7WzL-3MBcC2NDE9Y3dYCFn0k8"}',
            ],[
                'input' => '{"ciphertext":"FPprtRrKhsJ8qTN-6lG4N5X5cy1hH8oPqZsoqOCdHv37Hnx5xA2-0uQmDH2tOwkW-0QrVAnxauz109iaWh73HuCDpAp1CCo2qUrXpnJPKlV2MoZo3si0m-2BI6U3SLhGJJIXMg0RPy4HiZ02Z9KJ-WKmb5zZBcfLLLRnnFmq3p8I8FEcGG6iARGRflf_igLZwmln9trK8frKpDaDEC4ulhhpNhJdizshdony_R7M_bQ","iv":"ry-FYHMW7CoAxk2cO4genA","tag":"nEJKHS5s0bHY8fmZjq6yVnyveDAJVOK5vkHAnb73UEQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJXcEY5WlBXMWUtRmVPVUMxOXdnNlZkMkc3bzZWR3VzNHhYQlBFdHV3OHhvIiwieSI6InB6dUpSV2hDYTNORXRfWWJXb29jZEdSbUFlVkc3NXc5NUQyUEdrbzBuVU0ifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"HhBumvlu6A6yiBLB5KlFIVARgRirSVYRTJG53Wq581261bs0K7FHJAlYBqFh5LUjQrAg2emS2l0lprk-Aek7IIZeUgJMIGD4"}',
            ],[
                'input' => '{"ciphertext":"HzdfqiUAy9WeVN8pwBhjTowaT-yuK1Mo9gjPVuFNaBE9UNCYfgI87ZBmcdqH4kNs9TYkC7VtSZFNVz4zdMHDS9_z3oTrxXBaHpWcqaq6cKZMR1CPDXGoifyNS5p5sdc-xx8a_Afa8iFpMjbANyuughdCzBEEEzOiEy5B8Oo8g8PREegINDiRnGSD8GJvIzF5zpPzM7WZN3HY8t7nee0CDYAjn2sQ3A8","iv":"SmkaU0F9NyzW5RG2","tag":"4hI29h6o5L6km_Xr5rlChw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI4UDk2V0Y4clhZN19wRzdrUkplenM4S1pGeFphXzZsTkpxMmtYcGREbzNBIiwieSI6Ik13QmxSUERLQlFweG4wOEVjQlFWcnp3SkgtdW04ZkpERWxBdnZ5LWE0THMifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"Dg-Ii_KIKpy0MxyKb7O7hvrf73VrnKyS"}',
            ],[
                'input' => '{"ciphertext":"3bNpfUHaNOzzXMW_-MvMS3PzDWlPhe3m7_OVRl25gy5ZV8CotYi8bun19ilgYRFd0t2dRQEgj__JiezBjPUL_bKhjesv3xakiP_6_9qJ3TRTsgDyncReOiZWUGIN1uWAlkGZbcUVJfaXGCDYiW8H9jM3tjFo2LHvrDRuZ-8h9rXsvzBJavpShcgVeI6vO2S4lNJy2KnYXMyy4jXXCEGaC5uihycQ78E","iv":"aklvmCmGxXvn49ig","tag":"ug5Sg-6JDswn4icdhZY5jA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJhUFk1OXBkNzJEd0x0UVlIemowZWc0c194V2h0ODdEQm5VeU16THl3UG5VIiwieSI6ImFEQjdBLW1qSGw0elVGakl2MnJXUEFmUjRFUDZMQUZJQzNxR251RnVmM00ifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"_1S5xipc3i_eDdtb7qt1fwtQ9s972wvfRqo9WF_aW7E"}',
            ],[
                'input' => '{"ciphertext":"UDX9Rbb77maZ_K1pJ0Vue6dF7qx7Q_AhAvWMlBi4SqnGi0nzc_AHElmVn5Rr_YTPZio5B77_uI-6QsKR9P3pmjfudz8rB4rEdhF9a2CRsFFxifKoRqdxvVBtEtBRknQKCWEm9q7MhJsLmd1Ws1Hqn0eVP9yOqtjnAen15efuBQu7PNjMzq3xfGS1vFZfMzofds0Vfe_2qyhfjcVQhE72r6GVcDikb_s","iv":"jqBd1ZYenX3o5hc7","tag":"ioj8ijPnssSVPJGQP3VTNA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI0amNUSGo4MGNWNmZOeGl1Si1KX3gyY1NvU1BVcjFUZGI3cG9LSzhpeERZIiwieSI6IlpMeGI4ZHpEdzVOeEZNY0U2azFjT3dwaDBZV19RQUN1X0hnbDhiaUZvT1UifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"Msl7SnN8pXjK_FPU5iHLlpIJEUnp3z4tAw56CCezRHoVfrOyVKNKZg"}',
            ],[
                'input' => '{"ciphertext":"M_gvoPHSOBn8c49DDj76mfjmIGXm1NriaA4CE4FG5Pgn8UwwFltdNTPwVT2iH-Ayb4c6ElFk-temO9PiC9CCCqC-rysDljuJxTN9Hjk_okVCSBHVWcDRVtRSW-6OW-lB7XuSXlBxDt4Sde2LcoE00IsKB01bagDH6f9c63nK_pXPtlHr_TpWgRPk7a2hr7IrspRRqwWaoZIso6CRWao08q-YLWlGc7Lmv73WV9GKPKA","iv":"yYK-lvlV4DFw-VlJbQwNKw","tag":"FpJ37pb8sxiAjIcZu042eA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJ4ZnJSYWZncVAyOEpsSV9PWXNHYnhHZzZqM0t4SUo4VUlrdkEzdjhEWXl3Q0MyczBySDJYOTZxTkFuRDM5THVRIiwieSI6InZ3NTkwSnhqSFg2MzNBY0Q2WHlLRTYxTzRyR1BBSXRHbTA5TjZqTC13S1BMVHF1cUFYdW02MkRQSnk4amRRNzAifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"t6bki0dKvasNW1df-TYkWyTRmjhm4-d9fDPr2so7oyt-rd-l0V7E_g"}',
            ],[
                'input' => '{"ciphertext":"OHwGmnnvaRrsUyMaM4aHlM44nEgbcfIjs2xpCmzTtnoYmtEsh370uMe708WZBp_B6txyFH6EPoGrQBD6BPvitNoWri4ruFlOVrTrhH3daN1lGoU6MmAxps7MNCICAV2LNjlrMNwWqnIdppMI9-ibH8GDmYm3PJiBuFEuVu3Vjsj1J3CKqtdSd8CzP_KaXR_9ylDu-Gz2sKxolPeYWMfEo4FbGtgAQ2_gHZjzWWCufqo","iv":"rMlzmKArHSvS9Kokyuln0A","tag":"h0KmzQODzXf6HmveB-xXyQmVnDI06s7x","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiI0VXhiNV9qV1RWazI1RURZMWxBcUJYZVpCYWVLVVhpMjkzWkZMRG5FQXd4LTc3QVl4bmN2Z1RJLThFTUdLN3JLIiwieSI6Ik9ydlNYSE5hOEE1dlA0cHlOdmNJVjNOcEV1RmVMdEk4a3hvc2otQVVlMFVnN18xb0tCM19wLTlDUFNfR0dQR3QifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"CT9N2N8Y6tYAp2NmGQXT9wM7rB5jp4NgItK911Jg8-oCSIZBp1hgmebyFg2EBDWXFYJRZw75iCU"}',
            ],[
                'input' => '{"ciphertext":"H3mXaynLR1pD_gzvN71BrgIPUd2oE9L5twrOekQo2CpwnuUl8xnFxcJQSuLVVxQIDjlHO-m2EwCvhGHpyburyuGtq-O77Bm53Tri3-RhBqXvy5kQyN-m_ipcwafXYSxJeEqjEqQPwCnHMrmW2c84F6mXDH6l93z8XN0jj0PPRGD2B430Zfigy96JVGzylprvjXKNrD7idGlTEqxiNELYtxS47FKuaxiBjad3hM8H24s","iv":"2mO1VeTggaUOrWxBCV267g","tag":"v8_WYmE4VisWn-MrxM5aMGf3ZXn8WvKoFA-vfJ3OyiI","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJiT0VyN2tBUlpBb3BlMUlzdXVrS3A2ajJzaHlnb2x1SzhGU2pCdy0tY19KU1QwWlRKX3UzMWFlX1ZxeWFyREV2IiwieSI6IjhDSHlfeFBXSnZ5VDVDZUdmeWFLb1lqeDNrekswUnJiaUpPU01OeXM1LXdaN2dEejZKRzBGSVUwbW9lU0VPcEkifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"ua8MSPE-yf6eLEWgXz9GBNBJPMpCcjeNkRrbUMjTuf8xqiOq-co0Up9oJbOh_9rqcijeCdPGV38nnq_o7OEZOIawUDWSP2A6"}',
            ],[
                'input' => '{"ciphertext":"Ui_H1qyjQx7abNhd_oNs19bT1somgGLslXGz_BHQG4xdkMK2Z9JNb_P9xB6dWRNDsdT-MgNpIZs8Ky-j71vP2D_KlTXmbtdHCaGEf2_IEh1Ay6a1cOLX811_4b3zL2_w2WRp0mE2QwUmmC8jSl3wRGzG8841NFjoVaKvsJFjcKwR_JFY9MDTRP-r3lTxPY7OTUCw5oF90D5VIpGcKsHII-Q2SuLFzfk","iv":"dTdgc3OpfwUa82tm","tag":"ShvlvXgNJF15Wi9heg5VRw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJhWmp5OHhOVzdrWXVjZEdqUlRVYnFXUGlQUEdWZ01ydGNqVXJJaE1zVERLekxCNk9tcmtMMzJleDV1czBaOVptIiwieSI6ImJZMVJXOXNCZ3h6bEpiaDdkcjhnaUV3S1pWVDRuQTlIemtXOFFDM0VCM0ZFdGp1NHlVN2xIUTRWUFhZV25fSTYifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"2yET3wXH42ki1D9X-7PUYixLfz0AxqY5"}',
            ],[
                'input' => '{"ciphertext":"TjQRe9mnBasyb7AGRqmMIoUnLTPQwPE3OpuCESXXIOAeTjN-g0dH6bCS7eK6ixtgOmabpgH1JbGMMgIFMw9L1jgAIYtRPes8PNAIFBjgpmp96X5J6HSkY3bx9w-pTxO6Deh2TmKLoFiBSRfzIv7xB_aO5-7aXVdKAgE7rR4QyZ_TgIdqeCYR2GKRNSTd7t156G4DjraWjxteOMjsuZ_G5JJvQCFF4QM","iv":"2eUBFFFIEMqBzpim","tag":"4Kcu1lANTqDXoS0gE5t-yA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJqUHllT084NHl3c1c2UDJ4SEVEbWxDT1FkM0tKS0FRc0xoMzBHQ25xSFdLbUs4dnQ5YTFRTUszMF9lUEJIX1Z2IiwieSI6IkVDYXFlcjJlOFNyY0VUNkwyZTVzQllMSzRKZm1idHdSM1NlYUY0TllXczlwRjdfSjZMdlhWVEEtR242Y3gyUjcifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"PQJkM3E2VsZ2lvY1240O2clvplWAJj9Sn5uaMVy4LHc"}',
            ],[
                'input' => '{"ciphertext":"ZxuCUBTI0q09qLleYdJUz2TGKiH9hpWZEg7hLlKBfUysxccYSJOdUfESSmOK8-sRUPpXPMp6appBpbkev2J85tytYX9XWxDDBa3wTINLxI-ieBIOoiYuRvye-7wTmIWunwhNrrfwEWf2PCxShxMRIw2FkYRFlK0-nSJCwmezq62rAwJjqanGkbZv4yJfODb5IuGa6LciGGyWgAMvBlcA_vg76y_hfF8","iv":"bnPIuP0mgZ3C2E3a","tag":"-NhSfhgjlX4b063lsrobLg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJxeHU3ZTdQdGFzb2RNSC1zOEdrcnBzbjJmdGRvRWxaeTgzV3NXUXRRWmhVZmVGTVZZYmFuWE85NmNSMXVSeDZNIiwieSI6ImdkT3FJWlQtaFJCM25ycGszejVVT29NS1Nsb19PRnNvdHd6TVRHanFTcE5xSVRtMmc5RFFFMjZDVnNHU21ta0wifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"R9GPXlECKVnKa-KzXqb0ubgeagCIFdWb0xpzXb8rFaaA4-_TtVhn3g"}',
            ],[
                'input' => '{"ciphertext":"-G1Yi9oLh-bAW7M644d5Gn0nMCtT50T8Md_Y8SYwxlpw9AxDUyRscuMVRp17W0RO4CBiXLzdn73BiiBGbUYviqYAhyeFolTgehal8xsBaliEBNYjz_b7729p017hX-f2mfKZyR2GIdFJbSAcCEFvx1IRW_VC-aE5Coa1SMe_zgeCMig_MqrNUARP9fE4GGO-Fjw5gCX8k4MvHPGAW5MEVO-CEG9GNHH-KMV0tC501g8","iv":"JW5kYf9F1YqQSCWhkOCpjA","tag":"VqQ0TfKMvkqr3Z66jwDjZg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBZGxXbGVuYjIxSlVwamdDX1RyY3lrRllVSEROdW8tZ3lVTlNlWlkxTGNHN3g5UmdQTXBVUEV4YTNjZ1NyLUZ2TE9mRkVNa3U1NnRvN0JJM2ZXcnJOMTFOIiwieSI6IkFhbjNOcWxIVkkycWFLS0ppbVNneUloN1kyT0ZHRlMwTGJmZmNhaUl6am1uN3RBUk9BWlVrbDFnUUNJVE90OW95cDFyelo2OEhHQ011bi0tc3JrM2J0VFIifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"vfwkpfpm4EcmDBa8UT6FQ0KkSlUjCjNac80kCwaXYoF4jvkvTiiGsg"}',
            ],[
                'input' => '{"ciphertext":"vZIuoK_U_Myd0yLH_uhpS8Gjo8-VOU_pf8az7TvsMzTktxWae57CGXgzQPk22FoQhdp3SzD-kG8DbMurE28VoqD7VmN0r_NNIyndFFUAEN80o-j9nUhsez9XfP4ZwdefhF7wfQeTL3JhisKhf3swHFCwQB7J-7klOzyGZUr_N5u1loW6DE9HwCEFJbjNen_Ki_bPE956x-R0W9x4B7SYbri-15I7fKVcSVtqrRaJQqE","iv":"oT7PrVc_1VOsiFX__ZJNJQ","tag":"lwtI2gP-RcyQ2dCuuzBBItqCuQHsTgQ8","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBY1BjOHJzeFlKelJZRmQyM1IzSXhGMVVVV2V6RmR6bUVwSlhGQzBlaTNkdW9vV3pSY1dRRXZNLVY4MHdxZnRfUkRnVFMyR3VyWG1xNW9pUUVRSUhjMm9OIiwieSI6IkFYenFHVEdMT25CRWVxUnItbzBvZVQ0QUZERzR0c0xKU3N5Y2J4TUN5ZVZKYzdCNUFtYUFlSUw0d2h6SXZXdnJXWlFJUnJsWUl6MnVFbkRiXzhWc3pMblAifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"_IC57_UPVkNOCjJWhS7jC8rRregaNtI6CZDzt3oLkd5aR526-t48BCSBxFeDQHOLlUhy7p8Hlv4"}',
            ],[
                'input' => '{"ciphertext":"ypvP2KZXY1S-cs_j7FNOrad_2e2763x9sI1IU8TZy-I5w-Pgn3sRWm6PTSTsNUaOcDr46_isZ8EV0TBmfLIfT_hH7RT45Cl-U9bEyyTuoaiC7mOgs_lwtAQQPyOV_4da1eCBbG47feCj47bP6gNFe-lgDesXdZW_D-J06QZSP8iPm8F2daPapBlIY5lVvD99rXLIwxylBGf4EUDvfg14Fja5fQOaxZWDHLtRsQ9WMsc","iv":"z-BAqnirwIAdkqDfDyruVw","tag":"vTu2cS-5Er_p3ZC31K_YGQb3pnhqk2vfoaviCwS3ZqM","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBWTc3SGtWUjFJOGk3SnVoTm11UVRnQWVrLUxWQURwQ3dGbkhGWjBNOXdVWmVWenMxdk9EaXJkS0JhQV9vdmVWQTNYUFE2dUIyM0stRkg4ZkhfNS1JdUswIiwieSI6IkFLMThEWEM4Zi1EeWxiWlYtdWRuZ3FPa0o4QjZjcXVFZDhlTDhRM290Q1lXTW02Q1Y2bmhSekJrQUhQOW9zMVo4MWtMMDc4VWljUlRhUVBJUkdvS0psQWEifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"F9exm2MQH2wRd8gVQ3OY_LjUOBYdg2MSIjxqF1HiCgxvV4nmArpxVGehtkHJv5PHJTn6bK1H9E81I334S47DaQsYOFVAT984"}',
            ],[
                'input' => '{"ciphertext":"yoKrDLRaRwvekcpYrAc_Dq5lMcCYz3f9Bj56vRrfu5ojg5IpCZkQM5Zlq2lgkSBve8MKXlj3TNAOye07-69hJM0eBjZvEG4E10UAMbf9tczwj5AndRFRfwyik2WVSXM9eUBHeMiGbo5Q1D0c1ph4KQCOlcsGKv9HohMvgGqG8FXeYdkXcWz3eT5fPWCI_c54CCtn3eWDrmhE4O39quR0RLb-GWM9ARg","iv":"0UKjc8u8iq73YHm_","tag":"952mBU6NY7c8AA-YzfNBLw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBS3BrUDhINlAzS3FSSEFILTRVUXNZMkdMcjhVVWNTakVXOWpWNmVLUnlCWlVuTThFRFo2NkJ4TDRLMjgxQVhBM0RjWjFkcHM2MExzX05XWHJhTDFsT0UtIiwieSI6IkFSN2ExWUdPalZWTTNWWUpjTFpYODZtajZoTXJkMXU4WUdUcFp5eEVpTTlhX2NrOXoyQW1XNEkxcFU4WTdGQm1aUDZ2U08xQVNsQnhWT0Z0RjRZd24tRi0ifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"6bolT5ZriPlPxXi0Waxhh5km0C7CrX3P"}',
            ],[
                'input' => '{"ciphertext":"_u3Se62sIW7qtT7hD0Dszz0JfrhxDEC6o8xaOvNP2MaYCsJPDGYLFnlLECtJgA_uuDHQ_OEVD41XnZtlRYYWWP8-U6PvdeFu4g7exUD9djZlSNppcgE0GsiRzZ0izZRVh_zC5xsDCMsRb0DXqouDWIlFbLrJ27hT_pG8NDt4gPudVHPzWKDJjyIdTGUFCnSsl_Ls2pfxlTCUAndqhHP5orRGCk1Tmco","iv":"1lnmkUGj9GP3u-Rv","tag":"rkEYv3gHQ5M2zpxv61NB0A","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBUzIwRnJJX00zSmtsTUpQdFRRZ0hrMFMxOGstUlNTU25PeUcyN3EzNHlNZXNqaDFSdDJEaGRZZS1XaVdMVXZUZ3lFOHNZMUJ0dnJFdVFrWnctUlhDQTZmIiwieSI6IkFNNks3U1hSNmlWS0phblFhS3R2Y0kzNXBQd3BXWHczOEdzdmlIZmc5aV9MOWVqd2U5TUFZOU40OEE2cjlSQ3lSVnZ4aVIwMHZfc1VPVzlqZFlweXROV2YifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"4sO0aItNlgHmTmEVj8glfsg7emmETBoR1HjuK6-HQF4"}',
            ],[
                'input' => '{"ciphertext":"O3ny-MT3rMA_Q4NGqaQsxk7dfKBH_p3BKeDYGlN0w7bnFhD_u4yWLZB5Jy-X6hVZd3utagAoPPCo1trqmqDg9553lft-ub4onmnBgKyiLXNH1mt3LduWN9jH9fG4hRPnFI2osW5UhGgiT07szGMbdSNG_DAPXQfXt7pWbmBUQ5SQmZZUeQDo_D-uefolin9HKhxUq_RG6fN5CV39-dXBzrVx2yLAOV4","iv":"qm3eFJyoXgboX3Ta","tag":"Ieq-mcOLUaS-SBQKLR87KA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBRFk4cEMxTFBLdzhPd0JwTnFLZjVjS2tJVEFMUmdCemVJLXQ4N3NaWm12NjM5NGZ3bHVobjAtNXhZWnB3eEhXcU53T1lwdFM5aXktTmNCek5qT21wTFlXIiwieSI6IkFHckowOC1RWmVLMUdkY05tNEV2QndLQWdlZDJ6WmM5TFlIdFREcjdkU2ZUTHNUZENsLVd4SERHdW1Qbk4tbDNNeUltVFZzTC1LMHBqODB1bDhKeVRPdkQifSwiYWxnIjoiRUNESC1FUytBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"yjMwY4jutIBN2G0HJBWPMokMPJG9YMpYvhdrhsoVoZ-v4WjEPlcVzg"}',
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function dataPrivateKeys(): array
    {
        return [
            [
                'recipient_keys' => ['keys' => [[
                    'crv' => 'P-256',
                    'kty' => 'EC',
                    'd' => '_gUgAjx9zU5BKlHq--TiCjZmsdNQAgrv536DCTUM2vo',
                    'x' => 'Kuh77MGkweIENgR_3WjzJ4gEF47yn6yQWAeeNqYC5qo',
                    'y' => '1koAqIfb5C2PkCT1GYEcW4IcIEdrgOdMcua6G0Eyhtc',
                ],[
                    'crv' => 'P-384',
                    'kty' => 'EC',
                    'd' => 'Fn_Le74znJfY33TkqCoskx1pkgA_1sLnKvfvM_78lTZT2zfj4XC6uY_L8iRknOii',
                    'x' => 'o5CqgE0jIlCVwGKMXDsQmkOgxohJcod4hv7jo4h7qeRoysAV0YPtokMgv7CUpSCG',
                    'y' => 'Z3ZGVhyv3T-MudQI5fYNmkO1BzqlHQJHCQ9RQzqa05QOsUZo39gjVC2EhRv1Z9kz',
                ],[
                    "crv" => "P-521",
                    "kty" => "EC",
                    "d" => "ACebnk5N5RV4VFhrCmvp-5w6rsQJvHdvvBdJkIKmq3pDDreKC0vU-K2oYrQaX5vPuI1umnVw9qxFq6QCsShJ38Fh",
                    "x" => "AR05Z1Xe74_lcrJbhKg12jijs5LPbLwcpHDGETssYKRgbO3-4l7egk_WtLjSeXmDvRfkww9kKpFdKHTqmDYSIzxf",
                    "y" => "AL7NyrGpwcXqfvmQb4d7N6vO7REegUaFv8ea-_EXyA2eJciZJSmvipwpxRnoSfkNuJ5yJUGdjg_FtaddKaLdJEf_",
                ]]],
            ],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function dataRecipientPublicKeys(): array
    {
        return [
            [
                'recipient_key' => [
                    'crv' => 'P-256',
                    'kty' => 'EC',
                    'x' => 'Kuh77MGkweIENgR_3WjzJ4gEF47yn6yQWAeeNqYC5qo',
                    'y' => '1koAqIfb5C2PkCT1GYEcW4IcIEdrgOdMcua6G0Eyhtc',
                ],
            ],
            [
                'recipient_key' => [
                    'crv' => 'P-384',
                    'kty' => 'EC',
                    'x' => 'o5CqgE0jIlCVwGKMXDsQmkOgxohJcod4hv7jo4h7qeRoysAV0YPtokMgv7CUpSCG',
                    'y' => 'Z3ZGVhyv3T-MudQI5fYNmkO1BzqlHQJHCQ9RQzqa05QOsUZo39gjVC2EhRv1Z9kz',
                ],
            ],
            [
                'recipient_key' => [
                    "crv" => "P-521",
                    "kty" => "EC",
                    "x" => "AR05Z1Xe74_lcrJbhKg12jijs5LPbLwcpHDGETssYKRgbO3-4l7egk_WtLjSeXmDvRfkww9kKpFdKHTqmDYSIzxf",
                    "y" => "AL7NyrGpwcXqfvmQb4d7N6vO7REegUaFv8ea-_EXyA2eJciZJSmvipwpxRnoSfkNuJ5yJUGdjg_FtaddKaLdJEf_",
                ],
            ],
        ];
    }
}
