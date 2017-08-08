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

/**
 * @Groups({"JWE", "ECDHESA192KW"})
 */
final class ECDHESA192KWBench extends EncryptionBench
{
    /**
     * @return array
     */
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A128CBC-HS256'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A192CBC-HS384'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A256CBC-HS512'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A128GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A192GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A192KW', 'enc' => 'A256GCM'],
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
                'input' => '{"ciphertext":"9MutZxOrCe2iWclmxvx6QbHEp39u-oQm0HFqXpZZyiv_oHy0mDSXpgUC1ea_9BDz0XSAiS_fcGMJhHYf8lRX0HPHIr4hy5VfH-R8WtyBIB2L3936j6FvIHb3IFf9aP_54ZXaN4FNJ_rR5692DXaiNW-JoZZI6qQOHAb9bo78Hl_qruaTpKYafTUp52-takST5BNkZoA_vRGCml9sTXahxDaavGaaSn3eNu0awBIIZXc","iv":"W9zzdM7QHX7HtJz2t67t3A","tag":"2zEzNvoMnmB2Cg8ocfWJlA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJaVHIxWE55b1d4OXR4azdhU0hPVjlnTk9GeERNa01na1hvdWZYRFFZSTZBIiwieSI6InEwdG90X2dfeWZGQ2lwY3J5ZXFsTFNOSUVqajgwai1xV3FwVThIakxhUEEifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"sLB8Lr0gcL1jOWsQySfihXmrX8-0bmWnCmIPPF7GK0hKibGZIabXeQ"}',
            ], [
                'input' => '{"ciphertext":"3JXDx7L5DgBpwZsf4HjP6UdEjEW8DY1qGXIzbm6Ld6hVFBFNy4fAWdWkO6eR_Roht64Hg-JvE3fw6P_KqGpCbYWp1pMveK77zO17RMObm3XGd6H-JqY9NwLU5Rp_V3ysHeMTpaQguJD1P5P0yXfcLAcopGFzBgJAGc4-ahmnpNwAVZNs0w0n8ayGtZVx1L6bBaugMgrWOvcvAyJEACFb6JEL_LbXgUpSP8yaf5wyg5Q","iv":"vjmng9SsMo24zxA-VFiwzA","tag":"PhvCEi85K3wGbbS7HGnVV1uLI37qRcO5","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJNMWoxSzFsdWlMcW1TdjYzenY1MTQ5WFpZZUNDNFVCOVJiM29aVS1lYmVFIiwieSI6InJYb1N1UHhGdDkwNFhrVmNoazhrQzgybGdhX3Mza1JnVElUTTVldlFVNU0ifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"QTAevNDg3zReDxb8ntKciwN9VXu-iNUAnfGpd2nwnP0qHL-_gDGGD01Vti6K33ZIBOosOfvGB1U"}',
            ], [
                'input' => '{"ciphertext":"D0VT0Y58Ap9MY5saoFnupzdTVYztzoylseQIy7gSSL7bJvVNQaJ-8z3Gt9FcwiEkyFiF_zyvYC8J_X6ixI8kVOm8RJkCL6QdKFRPEcoowavxTXhW-sUHAozxO0x6bf5WXIHabGbNGkGe8_BZAEMS1--Q5tPT9Qz3DCyu1j_XSgz50J2Q55wN0OPBaN6AEVz2z_gC9Ca0gchSrL-8VRTOnqVJBzGfUwVA1u1bme49sfY","iv":"rLW15WwTWybYH2R653zbMQ","tag":"W87kkZsJeVwOzCR26oaragqxJMDtdDsglv5Kk_xhd_A","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJJemdNUjI0SGNhaktzenBZYW5IU2xib3BYRVRPYTBqWWhld2NzZ1dyRkxvIiwieSI6Ikt2Wlp2aU9RTTJwei11Q3dISDdqQTBwQm5qdTZ5NXRXdDMycWE3dU9uc0UifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"_Ke9GkTWcqGIzghfL2Fr-MtkoLDFaHxki8wNHewplIl6x8fN98sAVWC-jRoITHMB6f-WKj9lKDrrgf1XV1zStuWt9GeU1UbZ"}',
            ], [
                'input' => '{"ciphertext":"imQvXQeQkZ1kHAaoaD0usBnrj0fx7k8Q9OvYgwyqu__-kapNFK0RKL8aA8WndZKZfkRLOjHxwSYefoeAQLBEiZQcwDsB2-4gIR8vQ4LSk1Hzut_6YaUpqBiOvK8L4t6lxcSSlJrY05cVFuMuwWXtDDzSdwm5OXchqez4XU221NGElIpSz4_JqmGNJfGX2wbDVPtv0SYfD35p0Y7pLNOhDsvrVFzENrU","iv":"JoeSa-ssEv1401H5","tag":"NfbIhduObEcEjgyGHWnU2Q","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJpQy14UW1pR09ISm5LOERZYUxzeU9OZjFxVVFQZ0l1RzFYVkNpRUl4cmdNIiwieSI6Im92M1VQUlliRzduRzNrbkRNYlUwVmczMTZxR0Nxa3lvaWd6dzZlaEFnQXMifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"po8l475AtJShDazSRq5fA0b4bulbwqqs"}',
            ], [
                'input' => '{"ciphertext":"9DwVly4zlRmxIb_1MMuN2XyFJku_x25U4DcIaATYCUHoqHlmXrcpbvUIIX9_dWXEQY-_GsdPd_69PIJ2lbF7qYSD9p1V_e3kR7D2zKck-UHnGfPy6AQo6j4zyGys7AeEkpH0cEeKOGdBm9f8KNsAy39Yny899NKnXHjjm-V9z1N9uv3MImxy_-aU0McvaaLEUsmqHe8is4SrPLCAQhKxfgjggX4odLc","iv":"tqG6ux3Sc5-iJ67W","tag":"g4GytQ41BIJgSEBN0MKA5A","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJMcnlIVlVCb3NQT1JTRkxGR056NGlrZWtYV2l1SUluQjQ4NFgxTDJuTkpjIiwieSI6ImVmY1JEOUlFd21TUDIzZXhJZUxIaWt5NmN2dUVuWGx4bHNGTXpiVzAxU3MifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"xM7TQESE0sL-dGTRwp-nMOe9FUMBGEaIyq2WybvIQs8"}',
            ], [
                'input' => '{"ciphertext":"jCiBm3TLJ69-GvknFP7OyQrmL-4-t9U_GqcURZZhV_1_-IzQ_w96H5eZLUrOPsNz4au8Xs8aksG-Jcrlmopt1FS5zPATWCXFXKACJyky7N2u11AWJ0nxvWd9xZ6fZ8-UYHDZpq6sZHof-6R-7tTMult3FGj0Eqs0h9KmbKaORB2OjxYfYVO9BcjMSjApuVHEGWUmM2yXll2Uk8FbCoIId_m1ATwO8z4","iv":"Sw71tSDa_DUoSEG0","tag":"VWCQ59tc_NZwAEWVtWOGnw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJiS2hBRXhMbFM5aFZKbDVCQnRmUV9qcUt6MEdnei1qSTkxb0dneGJLZlJzIiwieSI6IktpUGo4QWhhT1lpMGEzZzNyeGxaOXFWTmc0dVc1UFBMNzYzVlZodDZnSGcifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"nSaz2dz4uBEFAMTeoJVH2R7eAvVgRNzV2z6gQ-zj_0cgytTyeKX9wA"}',
            ], [
                'input' => '{"ciphertext":"U6cBA1Hq7k6zzFBs8gt4oNY8t27dch6CWrwkgLyjdrJ02yGpRIpdnR-QazN4JHWWH0mhKTOkBhOj5wstX05SzjSlUk0Nb9TMywHOeTtQgbrRNvULMd9ebz3SEJyprUjyOmAxmzIQvQNulaoat_Jyh2ip5WuWGEG7depI4GmoHzWNZjkEJAdxjYL-5fe3RNqRTVwbYRIqRzV_Kx5ADylr79HUDhTKK5DYfXTSojghc5Q","iv":"kE1cJXHNM5qMBXb7m4zx1w","tag":"7uUzuYDF5WIDM0GMMfsIBg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJ4UGlQTk05Qkc2YzZNS2pYX1lZM01VdWhWQTVSSXA3U1ZBZkg5MFR4WnhTQkcxZGIySHNCN0R1dV9KZW1JOC0xIiwieSI6IkdtaHdmbWZHemxHbmItRWthVEg2dGV2NjFjTkVJUVJQQ2tmVjJsNFVDbkRveXAwNm1zUS04aEoyQzVqMEVNS3QifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"GWhp5Y5cTyTsKiHKxGZI4SXQFxlY8-Dg73goBFndGgFn5BiH0xWwjg"}',
            ], [
                'input' => '{"ciphertext":"RAHqXSvF9yxtiN4X0PdXt-c_R5akIKRpWgQzKbsDrPHYNmkTu7jpBB9xaACvgNsDNOmLFHvIQRzurimt7vADWMEqkch61WgT9JGcHZfsrHvWzYAPluNdMpvLrNF-iVrePz61K6BMuo8GR5n8ZWlgGnR66gZQa_TZsRUvFQ0zjct68EALW_Nyd9bLlcQnZtqgNSOAVrdCj2IEi2XLtBY6W6jC2FvAy-HJIubkjAnE78A","iv":"IwwLGHEXQPGsxacPQ34a9w","tag":"VoAcuM7fIUGl0-k5IqoX3PDtpeBUyMjf","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJZVDQ0dEdfeFNwcXpLMzJieUFyRW0xU3A1LXpMZWhGR0dIZ2gyclVnNEEwVm5XYkNrTE5oM0M4UHRLLV9yeUV2IiwieSI6IlhCMjRQSklVUEFWa1c1SVlnWjJJMHhmODRTQW9hS0pYeDY0Z092VllXcXZLNS13M0pEXy1sLVFtSzYwOFZIZlAifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"s8WSD8PSRKjsxQHx6uqRUehfYVf47jU3wzfux06Vz3lCA8n8b79katHdlAoBKAXmLgsm08Kp7Uk"}',
            ], [
                'input' => '{"ciphertext":"DeTXXK9JZB17FMP7elxLAo6v5g0cXDM1qCSZ9mA0atqdz5tQPLkjnVYbYZqAL9ni4ppgaaP0FkbmJwSJSBqHvK_E1AtSxezapAR_vOTrJ3OnshaSkCB1uUoni3xjCMS0RHxcKJecBjrJhWry-VYlyf3MV6hCAMAhchivY2LycXTmv5R_i9cGAv2B9ZqzGDnvB92WOUPdBJZl5gvoGKUQdAlSAaKHUW2ef6Ix3fy-dDM","iv":"UIhVTwPCsApFIptz59mcdQ","tag":"8hwCUClUABUCmUZ9tHVI0q4jo_78Dt0aZdaasOoq1AE","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJhZng0ZnNKaEN4Sl85SXBpQUNSazNpaTBkTm1aS2NyelE0bDVzZkxHQ1o3bjFiaGZ0aDJtNjY1SVV1YnVxSlFoIiwieSI6InhNLUFobTVjYXB1NEFpOVNZMW05RDgzMmJPd0YzUkJrbmF0ajJfczBQblJ2VnVWNU9GcFowX1Q0ZlNjVnNkSjcifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"vgkQSZW8N4-hiPa-IQbARnPFqxP7VzYNAVlwrFaoAsrbyVoWC1-7_n_S__7F7Y2ma0j9FQjFVj-ri947uxFNznbgW3D0uciu"}',
            ], [
                'input' => '{"ciphertext":"hyJq4flHGd7htwWVbhQwJ_pTqfrZ8oyqtZs2ipkPUIE6hX2X5st2BIvekKjrFIfqtu6Yzca-YcjTpQRv8JW8qdM8BCNS_aRnpRh1sbW9nEvacdRBddyMPIpduFs9IElNX6oa9dLQ_n6-FiW2QFHgzMgC4wRkllRZPzE1pzX2dHi7cS-czM2mHV-ZHUt8k2bKSRY_z9YogVyKPNnTBoqUvZTsaJXK5QY","iv":"PC_5VZzghUTsk1qG","tag":"ye16o2T5a081Vf01UVBPVQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJ5WTIwRndZYU9PRzVyZlNyWlhxVTR0d0FBblh1N056WWwzaDhMN0h2b0xEdkpRMk9zTUdaOGdzZEFnaVd5SGFxIiwieSI6IkMySUxaZXZlNi1XdmhIWUJEVHJ2cEZBVEVaWVlicEZqODhrVWFyaG5PQkFud0hWUE9YZThKN2ZoYzJLX1hDcW8ifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"H6AZPKqng48RIo1vPOmOnh_k13GksF8e"}',
            ], [
                'input' => '{"ciphertext":"74t5_xzUgsumndKpsJ5DMN1L_Imb10UU_bQJaLl_CdTr50BwZQr22iKIMDHmctCcUeT3JM8KZZY1ZCbeuNMRfHz08T3tv32v2eA42wgCtCfWfu1jZeuhyB6ZG0Ja_gUEV9XrLU8tG1DPsOqWrDx66-7xwqBSk_CKHAVpn-k9kP9PniCK2EtlqjQ7xcRpC1is5IxaMi0i30-5vfRR2XgeFD0debnpVuw","iv":"yRtjjS6UApCX1SEx","tag":"_sr3Gv_SN3JItUbP77_a9w","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJQSTNQMlRjeHJYRzdHazVFMHZPWE9YYURrM1dEU1ZCcWR2RURYRFJHTHFZRExsREpyTktVNFV5Wmx5ZXpJREZrIiwieSI6IlZ1c2pNVjhtcmdwN0Y1OW1uVXlZaDhycEl5SWx6T29NSExxUFdsNWhMQXowVVNva0RnS1pGdUwwOXBrdkl2cjAifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"NugJeNpMV-zn8DoxM1cghxv4HkC_9d2f8xIju0Mx4NU"}',
            ], [
                'input' => '{"ciphertext":"BHYEaf3boxSYf-hZO1pBzG91XH30CgCCGn0qmh5l3MM8hY82FXG0aLohlnJd-t07DRzceBB2UHbXlRMky5ZcbThm7WRJ455w4XRPt6fCcF0Pni5UotwGN9Pmbwq6aNFex25bCvFIv2IKsxATTP5EagOlboheWKEE5AJk_E1j00M_WFmNU5yrsMzHrKtKRkTlA9rdSskhPeTAo_l_WDomwODphwkq3rQ","iv":"QojGTtxsqOfnbbDt","tag":"HfFpFG68IBk0aruE8QiG5w","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJyNVJfU1ZnSzdFSXZjVXFzbXpGb0NJQnE3Y3RWbEg5dml6VXNiVHRUclBtZmttRFNGaHFoY2RsOHJUUkg4Z01hIiwieSI6IlB5UUJvRFl5cFp5MHlsMGNpRllSaWkzSkF2S1RFaVI4VklYb3Y4cF9hZXlBVlJpQXQycDZENW1KOTRmWko1bWgifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"BH7y7kGTEdxuO_mWy_6ZR-SNR5lihlinjZY0-25BqlAvT6f_JqQodw"}',
            ], [
                'input' => '{"ciphertext":"IegbeqPGpOMPJ34kNQnaBAlLODuXlEg-DCfWaDcZTD7d44MlqB0xfN3T0_dugyBUdPF6DkcEvXFqO3FmkQwAzWHdPLm7ZmD7KKofkPvpi_nkuf2_ahR5frv_9LxHkJmGuO-tccyIr2tFUzsNFFY-PqhdtWcjn4WvloN2KovVAqkWycOr9_jYUEiSikMx_aHrN105hIiaOAtpxknF-6K9j2k76ylTdpcmEiCmbogKKVQ","iv":"bPuovX_kL1iE24qqqccOsQ","tag":"zLmkHLyTZ3nhC4Wdsk7KdA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBRlE5blg0em1YU2Q3em9SUlgzRXZIM0NLbzE4QUpVRHlBaXllVXl1LTUwMlhxNjlTMWFTOEcyME53dnU1aGdSV0NmRGNPRjR6TDdNLS1vX3M0UDZNSUMwIiwieSI6IkFFMC1GTWI5MW1wb2llOVJtYS11MndNdXpDOWNmSEFWTUtWclh2amxVLS1BczRxdGhkT2xOOVNpeGYtMzZCRktGckIzZTZPRVFxd1l6anB6STVVendJdE4ifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"dhrCHuZrm5JYJe-vH7cgnKkx4dTKkRIQCzqM7P353eoEECKnhiesTA"}',
            ], [
                'input' => '{"ciphertext":"Upiw2XDmvCCLBBwWB_rVEEEny0NeuA7BQ7pDufAB0MRzcs_CM2zz20yesn_NYrX4G3PEsivHEsvNTTKbcBUHEhOdltljimYXWLBb2vRYwTC72bKi05DoalFyEcH-9HAYC3H2AtYspquAnpD19ijaYvnCw-lv5KjTtFY3pgFH9vsoLo930Gf_id0-ws4Aw3c-Dd7MRJqE2TahXK5Hu1CWtifKNK_jD1cOoM5S8hY3PBo","iv":"AcZft7uOdZo5zvioi_V0xw","tag":"OlreC-xjFbcqiaAPisJkZSHs2Xpkl9dm","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBZlpzaDZrV01maEhCeDZpRjFGLVVCRkJ0WTFxSndIU1E5WHoyWUtGQ0l5bXhNSnBLckJldHg5dXBXNWVWQW5EcXpHZDdWT3BHVEU2b3pNMGNsVDBiWEVBIiwieSI6IkFPZGZxaVRKQnFjUldtZmFjODh2RUhKRElfQWpnam1qRGh3Yjg5N3hQbWQtMnF4R0pZd1RPbmlaV3dPSHhYVzJ5RWNIblN2M2tuSkE0SlhxZEFRdG02Wk8ifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"SMlApBrZyNn7-NevqlJ1l7tN8yMuixIRdCLKgy1NAkqCq0Sv0R8gArjMx4O1De5gQ5LNu_0ClT0"}',
            ], [
                'input' => '{"ciphertext":"NKbREfNo1pFtEV9xzn9x6f8712zTK_jG1waPrdVO9N6LhpdvRCpadpRJnYYKn2R4PuXoPz1crjkX5iaOFdDcyIzbh15C6hDGrnMTS2ufPJxH5vY3Q8LKq-ByYeYBoFRrxJNJhXxsQoQPmuPn64u1_NuNm6eNJ-HzsP0nocpVgZ43GYyt-H_FEM2BSsypunW52Xn-YKl40Es2lhEjxWrcVriviFWdpwaUIGi7UzOCqOo","iv":"JR11L-plJ7lF5A1fT6NMXQ","tag":"Yh93Dc0R7x3lsjkHDuoPKBdDg3gSQlDRFrVZnyLuX5I","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBSGNXT205RS10SFNMOW5OVjVST1h1LXF0SThjQXRHUFo4bmUxUW12N1YzVkp1N1JsbzhxRVkzNDI3eDVBQk45a3V2aUtfaUlwQU1OX1EtWDhOckt2TDB1IiwieSI6IkFZY2NQNUUtZEVtcUtBNzdUWFpLenRHNTRlQ09SdjFXSjluSWdYV0JLd09obzRsajVwTDZMUV93bi1Bc0IwVzBBc2FoRWVqcEJuUmY4RDFnanY5Ni1hU2gifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"y93J7iWEAPKuyJSwKOWzNjGDT__0qN6Lq5gbZuupyggKkWByPMPU_vtX5DCVtokcVIa0-uSKVLFeBFNwOBpMbzDLcdDn9WFv"}',
            ], [
                'input' => '{"ciphertext":"4ulbeqBQMXYoKZSmFYgTSpCEvbh0ZqkTx8LWmQtzCg-InXsYj96kJspZHxwpZZ_D-PNwKh-HTWBKG5T3tYYjYg9eQlYxZ9ZwLFtalgCEyf2pBouBUYinW-SuftZyWPpIjSV5jdYz-Iyy40PUfNRIyC5qc0_xD9EVXodNyk4zNIEEi-D2EVFedNmjFXudCEI1yyG76PjMptciwjJ8Hb6SqKc8h-3jVjw","iv":"Mx8zToz8P_8dwIOc","tag":"yaw9cSfzhUn1F7wBoZ1q9Q","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBUUplSElfZGxDa1FzdnAtN2tUMHlCTHBSQ0ZtMUEtN3NQX3BXYXd2UHZLT1dkMWEzTGtvZi1wV1hmLVVTWVVudTBZU2N4SXFsT1p2bThTV0VvNmpEUmw3IiwieSI6IkFlaFVSRjdmRmlEc3FNaVdXS3FhQkE2WkxTdkJWZDVFZEdCLUlESl9zb0V2a2s2TVRUdEZ6dE1PSDAzTm9mdmJIWUprTWtKeUJrS2o1Zk41cmVLVEtvcHAifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"-74xZk5OchtvAeiDO0WSsjRo3sSKeE2E"}',
            ], [
                'input' => '{"ciphertext":"FzxB9rpky6sNZJzewBpYbasubuJtYGJaFytdo5PnoZ54d5TONLZn3h2ZQA4JFVqD99W-QktaRoA8HVtw5Maku0crynihQ8PNkA95NsuNp9FJca4zCGBonPnxvkp-OA_H8uc1_VkBuikiwgIDAwAK4T0syBCWOL6BpKN_jQusjkRt09qWysE-2uIdlgnV3z_ksxsaL6dROELAsopX4KJMyjY9I8hwMac","iv":"WOT7luXfy90np1sK","tag":"rY7XEmw4fMIIbEvPBoWelw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBU2puYkpVQlNGY3VQQnFKSklwU1h3RF9lNWtOTGliMWV5WjV4eldHa0VrNk5ZcXZzaDVqakJLQkFxVW5uZUsyQWFOVlZ4dzI2V3hTZkctWFlwNnc0Nk0tIiwieSI6IkFPTUZHLXpYV1hXeEtQTUpmdXlBcm1uOVoxMlU1VmVQTlNXUmVMaVQ3UGNDZEY2bWoxdXh6X0RydkZaQTN5b0VFQjVBcGNqUnNWWkdSdFMyc2tQS1RxUHcifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"4S-NfnnWYYb7ensZYDp_yW5CWutvNJW2JrLkTAaXy3Q"}',
            ], [
                'input' => '{"ciphertext":"H2kj2KfZhm1g7piKs4ogTYUtR9MhpxEWefNY2btxzxll2vmDoYRd_5NVWXtbr-EMI9WSBK7e-vSygBCYydl7zqkPdv17DsVo3gv5vaD4r0_BCQWuelde7UVFi-tk-nexqRSmrYrk2mGKgzsoeB80ClpZjl4HpYV82__djF5pZYNX2rPQ53oa9yX2fDtFTLYzZugZdp06ms3PBaJW3o_QNOLLOZTzHcQ","iv":"CLEnHgZs_2IPyzXm","tag":"k0RlMbVKy4MDCgnhO0fhlQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBWWZiTEJJS3ZNb2xiSWNUVDcwbDhwQWx6T3BaY1J6RXRDZ3JvZHRDVEZjZndYaVdOWTVCODJyUEJPNGExbEhuN3otVmFxMkdFMjdJSWFGZlRtdzVJLWljIiwieSI6IkFNMG9od2Q5UGJsY2pHcWFYRnpEYktqdXo3QWc4WUdDbU5WTExTQTVSVWlUclYzZkRFZWEtRmgzVXd1VmFqWnRxa2V2dVE3cFIzNzV4bVlUQzUwbnNGemcifSwiYWxnIjoiRUNESC1FUytBMTkyS1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"7SMJEfGbWX1Xm1-rn866d4rqNSIRBzGuG38BUg-FVNC963yV3FGiaA"}',
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
                ], [
                    'crv' => 'P-384',
                    'kty' => 'EC',
                    'd' => 'Fn_Le74znJfY33TkqCoskx1pkgA_1sLnKvfvM_78lTZT2zfj4XC6uY_L8iRknOii',
                    'x' => 'o5CqgE0jIlCVwGKMXDsQmkOgxohJcod4hv7jo4h7qeRoysAV0YPtokMgv7CUpSCG',
                    'y' => 'Z3ZGVhyv3T-MudQI5fYNmkO1BzqlHQJHCQ9RQzqa05QOsUZo39gjVC2EhRv1Z9kz',
                ], [
                    'crv' => 'P-521',
                    'kty' => 'EC',
                    'd' => 'ACebnk5N5RV4VFhrCmvp-5w6rsQJvHdvvBdJkIKmq3pDDreKC0vU-K2oYrQaX5vPuI1umnVw9qxFq6QCsShJ38Fh',
                    'x' => 'AR05Z1Xe74_lcrJbhKg12jijs5LPbLwcpHDGETssYKRgbO3-4l7egk_WtLjSeXmDvRfkww9kKpFdKHTqmDYSIzxf',
                    'y' => 'AL7NyrGpwcXqfvmQb4d7N6vO7REegUaFv8ea-_EXyA2eJciZJSmvipwpxRnoSfkNuJ5yJUGdjg_FtaddKaLdJEf_',
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
                    'crv' => 'P-521',
                    'kty' => 'EC',
                    'x' => 'AR05Z1Xe74_lcrJbhKg12jijs5LPbLwcpHDGETssYKRgbO3-4l7egk_WtLjSeXmDvRfkww9kKpFdKHTqmDYSIzxf',
                    'y' => 'AL7NyrGpwcXqfvmQb4d7N6vO7REegUaFv8ea-_EXyA2eJciZJSmvipwpxRnoSfkNuJ5yJUGdjg_FtaddKaLdJEf_',
                ],
            ],
        ];
    }
}
