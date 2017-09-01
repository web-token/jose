<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

use Jose\Factory\JWKFactory;
use Jose\Object\JWKInterface;
use Jose\Object\JWKSetInterface;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

/**
 * Class JWKFactoryTest.
 *
 * @group JWKFactory
 * @group Unit
 */
class JWKFactoryTest extends \PHPUnit_Framework_TestCase
{
    public function testCreateFromECCertificateFileInDERFormat()
    {
        $result = JWKFactory::createFromCertificateFile(__DIR__.'/../Certificates/EC/DER/prime256v1-cert.der');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"xEsr_55aqgFXdrbRNz1_WSNI8UaSUxCka2kGEN1bXsI","y":"SM45Hsr9dnUR6Ox-TpmNv2fbDX4CoVo-3patMUpXANA","x5c":["MIIB0jCCAXegAwIBAgIJAK2o1kQ5JwpUMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT\nAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\naXRzIFB0eSBMdGQwHhcNMTUxMTA4MTUxMTU2WhcNMTYxMTA3MTUxMTU2WjBFMQsw\nCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\nZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExEsr\n\/55aqgFXdrbRNz1\/WSNI8UaSUxCka2kGEN1bXsJIzjkeyv12dRHo7H5OmY2\/Z9sN\nfgKhWj7elq0xSlcA0KNQME4wHQYDVR0OBBYEFKIGgCZoS388STT0qjoX\/swKYBXh\nMB8GA1UdIwQYMBaAFKIGgCZoS388STT0qjoX\/swKYBXhMAwGA1UdEwQFMAMBAf8w\nCgYIKoZIzj0EAwIDSQAwRgIhAK5OqQoBGR\/pj2NOb+PyRKK4k4d3Muj9z\/6LsJK+\nkkgUAiEA+FY4SWKv4mfe0gsOBId0Aah\/HtVZxDBe3bCXOQM8MMM="],"x5t":"ZnnaQDssCKJQZLp6zyHssIZOa7o","x5t#256":"v7VlokKTGL3anRk8Nl0VcqVC9u5j2Fb5tdlQntUgDT4"}', json_encode($result));
    }

    public function testCreateFromKey()
    {
        $jwk = JWKFactory::createFromKey(file_get_contents(__DIR__.'/../Keys/EC/private.es256.encrypted.key'), 'test');
        $this->assertEquals('{"kty":"EC","crv":"P-256","d":"q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ","x":"vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U","y":"oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE"}', json_encode($jwk));
    }

    public function testCreateFromResource()
    {
        $res = openssl_x509_read(file_get_contents(__DIR__.'/../Certificates/RSA/PEM/1024b-rsa-example-cert.pem'));

        $jwk = JWKFactory::createFromX509Resource($res);

        $this->assertInstanceOf(JWKInterface::class, $jwk);
        $this->assertEquals('{"kty":"RSA","n":"xgEGvHk-U_RY0j9l3MP7o-S2a6uf4XaRBhu1ztdCHz8tMG8Kj4_qJmgsSZQD17sRctHGBTUJWp4CLtBwCf0zAGVzySwUkcHSu1_2mZ_w7Nr0TQHKeWr_j8pvXH534DKEvugr21DAHbi4c654eLUL-JW_wJJYqJh7qHM3W3Fh7ys","e":"AQAB","x5c":["MIICVjCCAb8CAg37MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\nA1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\nMRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\nYiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw\nODIyMDUyNzIzWhcNMTcwODIxMDUyNzIzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE\nCAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\nZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMYBBrx5PlP0WNI\/ZdzD\n+6Pktmurn+F2kQYbtc7XQh8\/LTBvCo+P6iZoLEmUA9e7EXLRxgU1CVqeAi7QcAn9\nMwBlc8ksFJHB0rtf9pmf8Oza9E0Bynlq\/4\/Kb1x+d+AyhL7oK9tQwB24uHOueHi1\nC\/iVv8CSWKiYe6hzN1txYe8rAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAASPdjigJ\nkXCqKWpnZ\/Oc75EUcMi6HztaW8abUMlYXPIgkV2F7YanHOB7K4f7OOLjiz8DTPFf\njC9UeuErhaA\/zzWi8ewMTFZW\/WshOrm3fNvcMrMLKtH534JKvcdMg6qIdjTFINIr\nevnAhf0cwULaebn+lMs8Pdl7y37+sfluVok="],"x5t":"4bK45ewZ00Wk-a_shpTw2cCqJc8","x5t#256":"5F5GTPOxBGAOsVyuYzqUBjri0R2YDTiDowiQbs6oGgU"}', json_encode($jwk));
    }

    public function testCreateFromECCertificateFileInPEMFormat()
    {
        $result = JWKFactory::createFromCertificateFile(__DIR__.'/../Certificates/EC/PEM/prime256v1-cert.pem');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"xEsr_55aqgFXdrbRNz1_WSNI8UaSUxCka2kGEN1bXsI","y":"SM45Hsr9dnUR6Ox-TpmNv2fbDX4CoVo-3patMUpXANA","x5c":["MIIB0jCCAXegAwIBAgIJAK2o1kQ5JwpUMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT\nAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\naXRzIFB0eSBMdGQwHhcNMTUxMTA4MTUxMTU2WhcNMTYxMTA3MTUxMTU2WjBFMQsw\nCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\nZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExEsr\n\/55aqgFXdrbRNz1\/WSNI8UaSUxCka2kGEN1bXsJIzjkeyv12dRHo7H5OmY2\/Z9sN\nfgKhWj7elq0xSlcA0KNQME4wHQYDVR0OBBYEFKIGgCZoS388STT0qjoX\/swKYBXh\nMB8GA1UdIwQYMBaAFKIGgCZoS388STT0qjoX\/swKYBXhMAwGA1UdEwQFMAMBAf8w\nCgYIKoZIzj0EAwIDSQAwRgIhAK5OqQoBGR\/pj2NOb+PyRKK4k4d3Muj9z\/6LsJK+\nkkgUAiEA+FY4SWKv4mfe0gsOBId0Aah\/HtVZxDBe3bCXOQM8MMM="],"x5t":"ZnnaQDssCKJQZLp6zyHssIZOa7o","x5t#256":"v7VlokKTGL3anRk8Nl0VcqVC9u5j2Fb5tdlQntUgDT4"}', json_encode($result));
    }

    public function testCreateFrom32kRSACertificateFileInDERFormat()
    {
        $result = JWKFactory::createFromCertificateFile(__DIR__.'/../Certificates/RSA/DER/32k-rsa-example-cert.der');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"RSA","n":"qzPFsFIf3cSes25DloV3y3d8gKMcZVE_EQ_6e_MZnyqDbuOEP39yQs3aunzbZRoO8Xw8lLoJNduiKKsco7odI753kBvz1eLyke-sWBVZttbnYyz9AE3ZXfAb9rHW2AxgIqHNsQOsLJS_douGZwxawNdE90WM4QG80bDpkxxHfObtmZIbZoOFSeokDHA5jokQGzJ65t6ARtQOIht84pIlAr8RO0vCUiJ0R4TdAffbdIukMcVfSoZBlZJ_q-yBtPoqB1Nmr1x1FqCtR81NrEtdp7CUHy4yLIskMzHTwJL24dx8zPS9RBIAuR6HO6soQwQgKY5NYmyaZGuWDrzw0Lor9_jjcx3x7NlXEUffGyUdT_bZ6owsgd-SpvnbqXPXIf-u5JH7afSUuajytHnGVilQOpEg06B0F-AumUEx8vdLPczCx0CED11mhRhT1eRQPJlzxgqA22SN1Yz0P55R8QbfFYcflpEtZbHmdvwMSipEoEUyI8aA9z268oNVnnAGhG3cOqk8-4HOvtqZ9LIc8jUcQLtWX-PJav9EePnWuV6pFwzvKcwl09m08xIfIh9DvFVJz3Fks-X6c1tVo2Valftlj8fnlzu9WgownkwhM4KN2UpcHcff4G-v9zckhcpROSzZ1ax5mPOUMF6B2OVawMhf3li9A9JEpBDxVu2-gZU6NbhvfH1f4PdNPUnlasPylHn4qz4S6_V1fuxho-2O_V72w3V5FDBi-m2D9vDVQvJtuoiJxUEyOWaxsenuzoFlq3jNHwm0SiabwVjaMyre4qktmHopLuLX2ixME3rbTtaXLAaly-t2X6oS4nFyhwP9f_WbJb4Yh_RDxksPj1hR_4nH43NTYjZBlLDM0YRb4xRzFmATQOUhPou6LSUbl8Tl2z7WYFzlcKgHwkWRaTGUV8Sz_h-_IfgZDvCtyyLhzvWOmfJBhsV1nTbDrr8DivZGH5huBNH88v_gbCVw36aAjH8BnmcHQ0ImUUwXoiB1iWSWB3x1xdYnAyQf5RV2PK86wVc4EBRxW6MeJHWZr-kFgHtcwk2ys8MewL8xlKs1S64APAWtD-WsLGEnUVMfM5EuWjoS9kB4BI4DC6M0uyDjaCuFu80wMmWfx9C3-Y2x7l5Lw0G4gRcUk-F3ONtKfsxMqAmV6aUVkXmdkX5LLa105CpIVqflM40CPl5mlVGEFlTf9u0zclyQ0_-qWt78ZzkpolPj9XKHikdYA_DKbvtfgtgNC07GIwBctoQsOrKGOxigeWzrAwfS9S5Wt7hvcs2R0Y04rXoeSTPbHWLumsJYLxC2HPtam3IxQJzCljIOFB5Sqi9WLO5l_yjmUGS2Fzy5DkuyFuC3o79rB-Vu0zpHQ5sHdbyYkfvi3QZx4jLuj2ki-3_1Qj7RfVdd1yWeudnFUy5QGfWh3-VoaK9UIZ1EeX62owXTGNOJovn9yMdwbXmy75qrkPXadFQG3lnuqq_Ucd8ZAYJvwfQb6uhTSv1kSFCpxyyaSBYjLU44QDF6FRh_QHLMBM2DVasOT0hsF2UWsIXUneoJHk_qVZSRmj5EDaIrWAUEZfL_geiwcW3_L3Y9iaHMkB93fHNsVEpLmTO-vLHZHYN0c-kKNVBw_40xGZ5ZgPJlT4JZVvBKuB2ka2OsSLcRXZvzZZZTnrRHb_9dngGkFpI0gc6gFu2d1mPIIFp6JS7AJ4_sYKE4yxuGG7IsA4ErnNBEK9Sr1XSu0_KfcIv63dm_AybDg1vmqMLCl5EiP9OIFsWdIM42970PH9h8Ri7KUn0D53RSRVkV38NW312A2JYCHfEfbIxyibEIrsusib98x6Bedh-3BpsWyih2XlDT6AFwJdD0cc_Uf56Vqv9waUtsSx-1xBwliZ35MKq-IfV6hcLnFgLhxsqakV8aFLAEzI8Ulned6zjRAC28aaDOZcFdKEMD0wHPUW8-9UTQxAgug8otEITWSkKubyXbdofpVa9Xwjq1-jLb4eylqey0RokKrHO6B7F3KtUF8Zsm0mGEg7nvUhjEBFL3AqkLke5Nb_78uqb3tzZF3iO6ghENar9s1DUIYqNkbMSeh7smgER_PBUB0MGMqRnx8qcr5t5yBEurZ7qq7-LYoJOoc6UwaPrQN_AFRou4ugiRrxIrvOwrDPr4y2zoi9XKnBBuYMnt2AkGVCNIA0WOKgmex4x_2Nri2JlRieAPwNPfW5PLkyPVRfw0dNzhg7csMl1Wctdw1JpHJhgMswuhYhRWGyzYWE4ZU8lvQWqA42MOKfUixAV4LmEzGz2eRQSPGWjLC85-mcxf_vssmD-mbuJAjzlLDzzwllrTDCQrt18DftpAAHhD5hG2HmQH9RDzcS3sniIx4p2zyqBHVQsWM74BlQjbODjgHRHerTgxYaNmh4KRA38lmb9omrUhI2Q0Lj5CF2of_Apd7fo8u6LpBpdEtirkn_7-9vPPiGerClV6lSjoNi_I_hHCneAq-3KZq7hM5XliJPvUrws_m0X5n6_fazdk-gOohEuF0Aq_1I5633sS-DGrFyan2K7oeoBGQN994-kweTR0lLko14nC5wnvizbsv7sDUNJTjM7LMYIrhKEILTjjGQ6WuCkYhQuM4RAnx74jFIchW8pS1tEnUcIOyBWgFB9M2zdbNmJg7vH43mmX408jMYVKs9CQz2Y7Vu33S0dSp9sWxM1KUREFVy1xTbVgKNxLxOzXiLOjm_b4EifAHZh_KTf0POm5RESU-TSrO29y5puTHL-PLuOE30jrxXaKhW5UzmQLUMhBGI7geYP6fE6QxyUi0gD_tLdMmzxTlZiOXkE6HnBQ-3Ar54uA-RFUhnzU-XT3wm--eINsvqyrHCyLQlmM71aBXnMlH5g0NJjdm42XSecTopWfFCfcNe1-ufpUuMGGg0C3LxVN5fkTmB2_6gai0AHh4dNhefGkKCZ5OcSNtA_UUI1nKr_wgPTI4X1catN9RE9mMYhOt-I5gOVRCihxDcUcBl2apUaFK-jHPs5rABqhykbi_dOS-zy42I86Vcu4B-_0GNlRIPRLZWFIhNRy_kfCOq4kb4SK9DjTvHsaq6YWMoL9Jk3JiqvH4yrMZ6T-XEFdJ8DGSc41lo1YJwhFUu0eGbGFKxyUBrHv1l9ByPrqWaiepnBBsda4y8G3SoiCfndwkbvLeE5ykYgurPpkYX_bau2PqsoAkiJ_GmbitKpXD71C5PmzvzLvpxkgC6hQq-v4L4WLelADvBpeikX9k23qhR5H3mkzNeMZgHyoFisy161cDgOlcg64g6C2UzJKlb5C1tOlQwM3fdm7cjBJXOjuxgi8Ewx6ov90eeaqIEfFvnUu1_IC_tFve9P_Us21Ak53vwStlHueYHtedJsHg84C5Ppt_z1LFR3Hh8m1pOnlb3kJw5eGpvsXweZrIIN0cvwz-NZ_orIxjPxLf23wy-y-lhObK17BfX1g-p759XtRSaG4Rj_QedauXHAA-SKgvwAOY3kBuWo9Oxx73JbC1kov55TkecHj2lXO_o49O5LCOa_h0nHIVb3JIGWot11sF_6zwNzFM2WtHFNu7Iu9hllumC8rvz3HEbylvSPQYzBQKy8NSyC6T9wbH6cAYY-vl59q1J4DwBH3DHKoMAec8InlnBO_ekJa8SMdQMZxov0BaxJc0W__29w2Sza0cBsMslfpRIWRWMb4jNpyvCyEVxrGf7AakOl0_9P3JCQ2o8cuf-BGg_z_iQ3aTMYVWi_pWuxnhh5NchjQU8C3dxvnEd0Te9mmDlvZh-N9GULo0tlzHz3WZniUp7mxVQ3nkeS31M0LIIF3SetSMjXrGJ_4bzAnb3EjH44eFuvgOiJ8ChXLCmHLtIpFa0WSC6YVpBxqfPrxke-DyB2Lvz_46MSQ4iKvCFhdYWxBtwXCZDN5Dt4XFpMknL_VnuVU8a5_rRqpEebv_VF1pBZsvfTK6UXFWAApFvL4ebApuLsFInG3uk89N2SbenTTiBGWZWZjsEFsvf3iSFZdQ2bgKSLmJIsuXV1mUPkzGEr8SsPLDKhGNZBevtka-CfnukEPn7a3K_O5sYcccEtYwx0VNiC6dWu7B_-pflffa1m4pbhdg6KfykDO9_jU_LE692dhWUzbv977zGUlOnmsEMeqmSTo9V5Hv0UsEDGEjoe9piKidoZ8JdAq1WIpSBfW9M2wtkZHbi2nlaBnKJuTaaNs_nWjbG4y73hEqEqRlQMKrLsJU7rsmy3h6x6-J_tXfkKpWu_Z_PhR-ca2RV4ldwUNejBhBomg-6bcSq1lHXGTpwc0wSDmIUfE2W6ZZysaFpmGpTDFjTDqfeeAwwbzShK7Uc-OnJVNiQ5w1KALJNjXURSfI61vyWRBMtFHaC7t6ixwDfv6pqEa0xeDe4xf4Z1qdX1Zfs4xpdAyzZWmslUsXIYDtiTXq6NYGjnCEPYqneVGOWhP6re0UfzeqqB6p6_L42UoqFrrjU7jnEWRlz6gxdU9qOJgLX3u6CIYtN6b44tpsqA23fNBiuf4SqoYimbd2YVjXFRFFNZ2XqJ-wBqYcD5xIfudMN6W5cAD4p5cTQ11_-EqIp8rDxiWOs-PN8SQTIE7ZYQ6na-lSITpchNybreE9SqhzluoY71DN8oQuUJHonrAW5Hh_VroGBxpbO9XdNhw0XrC-S9iH9DDEUedanM2DznPUZsHHutG8H0K9AEyWRS01sAwrF73ZG57qy5IciYMHZuFbkY0lzwbF-vd15jgNfP4JTmZD2sVWwVgI7Qp9T2hd0uuZL_huHl2baRCyC_DSI9c6p3q9Ud_tBN_yCcNcUVx0rS6EGfzM8VYOGwyiBVBAgVDjBXiKBsUVWA3ljfOtYhLKBDHkqhvoQaczSI2fKX7L7cwgXeBdckoaNhno6mCpZBamuyBZ1Iy6TnguQi59MCCKdiczIpfeumbSDEovy2IbQmPqld_JI6WOufgldiITu3hXR5KNazan2mc3NrKu1SEXZpdzb4wJZZ26U_1xE2GLMJru05yZoVNEkN72DhagM1R5oqHwPzRcn3ahdYvUzDoP6UHEpa76A23lqafY7F98l66hmAnXXlEKzEVwthYoxWANYtVsxs9NktNJdNMB3OCMnCo9BWkefmjlrzMJSkBP_1mfxN2o3W1tMNXpk5OQPO20_eWPF3iYhobSo8fcxzXtw9bg1BXr0TADj0hl_z4jw93wVGGLlsA3qYstay0I9yJgHBZmhxc7V1JzNWdwxIDmRgA5eCm1ELVBxpIup9WGZlUs1rzwqXzI-37i7l3dwFfCf_i2g8m-gNQjuM6YqkSz-XKcn-sJEg1XSMhoB15sgYE9U-2Oe-_EGLK0dOU2zyHO40F8ghvhKWpuAcITX_QnEMremwsiCl0PEnGZ98BXzlRvd1MFNc0ZUwzN-wTVxs4jNkteNbp0MjIKA5Y6FiCEX6koNWY9cLXSNg4XG4IsWRQrfIn2WWFz_nhzlaZNm_NUM1kmKRREPmsvQ","e":"AQAB","x5c":["MIIR2jCCEUMCAg4EMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\nA1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\nMRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\nYiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIx\nMDEwMTIxNzQ5WhcNMTcxMDA5MTIxNzQ5WjBKMQswCQYDVQQGDAJKUDEOMAwGA1UE\nCAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\nZS5jb20wghAiMA0GCSqGSIb3DQEBAQUAA4IQDwAwghAKAoIQAQCrM8WwUh\/dxJ6z\nbkOWhXfLd3yAoxxlUT8RD\/p78xmfKoNu44Q\/f3JCzdq6fNtlGg7xfDyUugk126Io\nqxyjuh0jvneQG\/PV4vKR76xYFVm21udjLP0ATdld8Bv2sdbYDGAioc2xA6wslL92\ni4ZnDFrA10T3RYzhAbzRsOmTHEd85u2Zkhtmg4VJ6iQMcDmOiRAbMnrm3oBG1A4i\nG3zikiUCvxE7S8JSInRHhN0B99t0i6QxxV9KhkGVkn+r7IG0+ioHU2avXHUWoK1H\nzU2sS12nsJQfLjIsiyQzMdPAkvbh3HzM9L1EEgC5Hoc7qyhDBCApjk1ibJpka5YO\nvPDQuiv3+ONzHfHs2VcRR98bJR1P9tnqjCyB35Km+dupc9ch\/67kkftp9JS5qPK0\necZWKVA6kSDToHQX4C6ZQTHy90s9zMLHQIQPXWaFGFPV5FA8mXPGCoDbZI3VjPQ\/\nnlHxBt8Vhx+WkS1lseZ2\/AxKKkSgRTIjxoD3Pbryg1WecAaEbdw6qTz7gc6+2pn0\nshzyNRxAu1Zf48lq\/0R4+da5XqkXDO8pzCXT2bTzEh8iH0O8VUnPcWSz5fpzW1Wj\nZVqV+2WPx+eXO71aCjCeTCEzgo3ZSlwdx9\/gb6\/3NySFylE5LNnVrHmY85QwXoHY\n5VrAyF\/eWL0D0kSkEPFW7b6BlTo1uG98fV\/g9009SeVqw\/KUefirPhLr9XV+7GGj\n7Y79XvbDdXkUMGL6bYP28NVC8m26iInFQTI5ZrGx6e7OgWWreM0fCbRKJpvBWNoz\nKt7iqS2Yeiku4tfaLEwTettO1pcsBqXL63ZfqhLicXKHA\/1\/9ZslvhiH9EPGSw+P\nWFH\/icfjc1NiNkGUsMzRhFvjFHMWYBNA5SE+i7otJRuXxOXbPtZgXOVwqAfCRZFp\nMZRXxLP+H78h+BkO8K3LIuHO9Y6Z8kGGxXWdNsOuvwOK9kYfmG4E0fzy\/+BsJXDf\npoCMfwGeZwdDQiZRTBeiIHWJZJYHfHXF1icDJB\/lFXY8rzrBVzgQFHFbox4kdZmv\n6QWAe1zCTbKzwx7AvzGUqzVLrgA8Ba0P5awsYSdRUx8zkS5aOhL2QHgEjgMLozS7\nIONoK4W7zTAyZZ\/H0Lf5jbHuXkvDQbiBFxST4Xc420p+zEyoCZXppRWReZ2Rfkst\nrXTkKkhWp+UzjQI+XmaVUYQWVN\/27TNyXJDT\/6pa3vxnOSmiU+P1coeKR1gD8Mpu\n+1+C2A0LTsYjAFy2hCw6soY7GKB5bOsDB9L1Lla3uG9yzZHRjTiteh5JM9sdYu6a\nwlgvELYc+1qbcjFAnMKWMg4UHlKqL1Ys7mX\/KOZQZLYXPLkOS7IW4Lejv2sH5W7T\nOkdDmwd1vJiR++LdBnHiMu6PaSL7f\/VCPtF9V13XJZ652cVTLlAZ9aHf5Whor1Qh\nnUR5frajBdMY04mi+f3Ix3BtebLvmquQ9dp0VAbeWe6qr9Rx3xkBgm\/B9Bvq6FNK\n\/WRIUKnHLJpIFiMtTjhAMXoVGH9AcswEzYNVqw5PSGwXZRawhdSd6gkeT+pVlJGa\nPkQNoitYBQRl8v+B6LBxbf8vdj2JocyQH3d8c2xUSkuZM768sdkdg3Rz6Qo1UHD\/\njTEZnlmA8mVPgllW8Eq4HaRrY6xItxFdm\/NlllOetEdv\/12eAaQWkjSBzqAW7Z3W\nY8ggWnolLsAnj+xgoTjLG4YbsiwDgSuc0EQr1KvVdK7T8p9wi\/rd2b8DJsODW+ao\nwsKXkSI\/04gWxZ0gzjb3vQ8f2HxGLspSfQPndFJFWRXfw1bfXYDYlgId8R9sjHKJ\nsQiuy6yJv3zHoF52H7cGmxbKKHZeUNPoAXAl0PRxz9R\/npWq\/3BpS2xLH7XEHCWJ\nnfkwqr4h9XqFwucWAuHGypqRXxoUsATMjxSWd53rONEALbxpoM5lwV0oQwPTAc9R\nbz71RNDECC6Dyi0QhNZKQq5vJdt2h+lVr1fCOrX6Mtvh7KWp7LRGiQqsc7oHsXcq\n1QXxmybSYYSDue9SGMQEUvcCqQuR7k1v\/vy6pve3NkXeI7qCEQ1qv2zUNQhio2Rs\nxJ6HuyaARH88FQHQwYypGfHypyvm3nIES6tnuqrv4tigk6hzpTBo+tA38AVGi7i6\nCJGvEiu87CsM+vjLbOiL1cqcEG5gye3YCQZUI0gDRY4qCZ7HjH\/Y2uLYmVGJ4A\/A\n099bk8uTI9VF\/DR03OGDtywyXVZy13DUmkcmGAyzC6FiFFYbLNhYThlTyW9BaoDj\nYw4p9SLEBXguYTMbPZ5FBI8ZaMsLzn6ZzF\/++yyYP6Zu4kCPOUsPPPCWWtMMJCu3\nXwN+2kAAeEPmEbYeZAf1EPNxLeyeIjHinbPKoEdVCxYzvgGVCNs4OOAdEd6tODFh\no2aHgpEDfyWZv2iatSEjZDQuPkIXah\/8Cl3t+jy7oukGl0S2KuSf\/v7288+IZ6sK\nVXqVKOg2L8j+EcKd4Cr7cpmruEzleWIk+9SvCz+bRfmfr99rN2T6A6iES4XQCr\/U\njnrfexL4MasXJqfYruh6gEZA333j6TB5NHSUuSjXicLnCe+LNuy\/uwNQ0lOMzssx\ngiuEoQgtOOMZDpa4KRiFC4zhECfHviMUhyFbylLW0SdRwg7IFaAUH0zbN1s2YmDu\n8fjeaZfjTyMxhUqz0JDPZjtW7fdLR1Kn2xbEzUpREQVXLXFNtWAo3EvE7NeIs6Ob\n9vgSJ8AdmH8pN\/Q86blERJT5NKs7b3Lmm5Mcv48u44TfSOvFdoqFblTOZAtQyEEY\njuB5g\/p8TpDHJSLSAP+0t0ybPFOVmI5eQToecFD7cCvni4D5EVSGfNT5dPfCb754\ng2y+rKscLItCWYzvVoFecyUfmDQ0mN2bjZdJ5xOilZ8UJ9w17X65+lS4wYaDQLcv\nFU3l+ROYHb\/qBqLQAeHh02F58aQoJnk5xI20D9RQjWcqv\/CA9MjhfVxq031ET2Yx\niE634jmA5VEKKHENxRwGXZqlRoUr6Mc+zmsAGqHKRuL905L7PLjYjzpVy7gH7\/QY\n2VEg9EtlYUiE1HL+R8I6riRvhIr0ONO8exqrphYygv0mTcmKq8fjKsxnpP5cQV0n\nwMZJzjWWjVgnCEVS7R4ZsYUrHJQGse\/WX0HI+upZqJ6mcEGx1rjLwbdKiIJ+d3CR\nu8t4TnKRiC6s+mRhf9tq7Y+qygCSIn8aZuK0qlcPvULk+bO\/Mu+nGSALqFCr6\/gv\nhYt6UAO8Gl6KRf2TbeqFHkfeaTM14xmAfKgWKzLXrVwOA6VyDriDoLZTMkqVvkLW\n06VDAzd92btyMElc6O7GCLwTDHqi\/3R55qogR8W+dS7X8gL+0W970\/9SzbUCTne\/\nBK2Ue55ge150mweDzgLk+m3\/PUsVHceHybWk6eVveQnDl4am+xfB5msgg3Ry\/DP4\n1n+isjGM\/Et\/bfDL7L6WE5srXsF9fWD6nvn1e1FJobhGP9B51q5ccAD5IqC\/AA5j\neQG5aj07HHvclsLWSi\/nlOR5wePaVc7+jj07ksI5r+HScchVvckgZai3XWwX\/rPA\n3MUzZa0cU27si72GWW6YLyu\/PccRvKW9I9BjMFArLw1LILpP3BsfpwBhj6+Xn2rU\nngPAEfcMcqgwB5zwieWcE796QlrxIx1AxnGi\/QFrElzRb\/\/b3DZLNrRwGwyyV+lE\nhZFYxviM2nK8LIRXGsZ\/sBqQ6XT\/0\/ckJDajxy5\/4EaD\/P+JDdpMxhVaL+la7GeG\nHk1yGNBTwLd3G+cR3RN72aYOW9mH430ZQujS2XMfPdZmeJSnubFVDeeR5LfUzQsg\ngXdJ61IyNesYn\/hvMCdvcSMfjh4W6+A6InwKFcsKYcu0ikVrRZILphWkHGp8+vGR\n74PIHYu\/P\/joxJDiIq8IWF1hbEG3BcJkM3kO3hcWkyScv9We5VTxrn+tGqkR5u\/9\nUXWkFmy99MrpRcVYACkW8vh5sCm4uwUicbe6Tz03ZJt6dNOIEZZlZmOwQWy9\/eJI\nVl1DZuApIuYkiy5dXWZQ+TMYSvxKw8sMqEY1kF6+2Rr4J+e6QQ+ftrcr87mxhxxw\nS1jDHRU2ILp1a7sH\/6l+V99rWbiluF2Dop\/KQM73+NT8sTr3Z2FZTNu\/3vvMZSU6\neawQx6qZJOj1Xke\/RSwQMYSOh72mIqJ2hnwl0CrVYilIF9b0zbC2RkduLaeVoGco\nm5Npo2z+daNsbjLveESoSpGVAwqsuwlTuuybLeHrHr4n+1d+Qqla79n8+FH5xrZF\nXiV3BQ16MGEGiaD7ptxKrWUdcZOnBzTBIOYhR8TZbplnKxoWmYalMMWNMOp954DD\nBvNKErtRz46clU2JDnDUoAsk2NdRFJ8jrW\/JZEEy0UdoLu3qLHAN+\/qmoRrTF4N7\njF\/hnWp1fVl+zjGl0DLNlaayVSxchgO2JNero1gaOcIQ9iqd5UY5aE\/qt7RR\/N6q\noHqnr8vjZSioWuuNTuOcRZGXPqDF1T2o4mAtfe7oIhi03pvji2myoDbd80GK5\/hK\nqhiKZt3ZhWNcVEUU1nZeon7AGphwPnEh+50w3pblwAPinlxNDXX\/4SoinysPGJY6\nz483xJBMgTtlhDqdr6VIhOlyE3Jut4T1KqHOW6hjvUM3yhC5QkeiesBbkeH9WugY\nHGls71d02HDResL5L2If0MMRR51qczYPOc9Rmwce60bwfQr0ATJZFLTWwDCsXvdk\nbnurLkhyJgwdm4VuRjSXPBsX693XmOA18\/glOZkPaxVbBWAjtCn1PaF3S65kv+G4\neXZtpELIL8NIj1zqner1R3+0E3\/IJw1xRXHStLoQZ\/MzxVg4bDKIFUECBUOMFeIo\nGxRVYDeWN861iEsoEMeSqG+hBpzNIjZ8pfsvtzCBd4F1ySho2GejqYKlkFqa7IFn\nUjLpOeC5CLn0wIIp2JzMil966ZtIMSi\/LYhtCY+qV38kjpY65+CV2IhO7eFdHko1\nrNqfaZzc2sq7VIRdml3NvjAllnbpT\/XETYYswmu7TnJmhU0SQ3vYOFqAzVHmiofA\n\/NFyfdqF1i9TMOg\/pQcSlrvoDbeWpp9jsX3yXrqGYCddeUQrMRXC2FijFYA1i1Wz\nGz02S00l00wHc4IycKj0FaR5+aOWvMwlKQE\/\/WZ\/E3ajdbW0w1emTk5A87bT95Y8\nXeJiGhtKjx9zHNe3D1uDUFevRMAOPSGX\/PiPD3fBUYYuWwDepiy1rLQj3ImAcFma\nHFztXUnM1Z3DEgOZGADl4KbUQtUHGki6n1YZmVSzWvPCpfMj7fuLuXd3AV8J\/+La\nDyb6A1CO4zpiqRLP5cpyf6wkSDVdIyGgHXmyBgT1T7Y5778QYsrR05TbPIc7jQXy\nCG+Epam4BwhNf9CcQyt6bCyIKXQ8ScZn3wFfOVG93UwU1zRlTDM37BNXGziM2S14\n1unQyMgoDljoWIIRfqSg1Zj1wtdI2DhcbgixZFCt8ifZZYXP+eHOVpk2b81QzWSY\npFEQ+ay9AgMBAAEwDQYJKoZIhvcNAQEFBQADgYEATPINk\/17H+RLz459iCVQAGes\n8kc5sxYj3CkMlWrGMiCxvsgu2kak6dCa0f3DfiVt54Fry7s0OklHiZmipoiF4RCt\nyJwUSAzRrZFAbkpDg8oIu4Ui\/Bt13kY7xON+u4m0IgkLZSE+8BSjMrfjVvVxe+qH\n5i7X\/ibUTDjgyfdA8XI="],"x5t":"KGApLybHWJmBwZGgBk07AlRD9nU","x5t#256":"YD12k6kc4xuh_5vEHMyyOFpGs6VqTyaKMlxg0Nt2crA"}', json_encode($result));
    }

    public function testCreateFrom32kRSACertificateFileInPEMFormat()
    {
        $result = JWKFactory::createFromCertificateFile(__DIR__.'/../Certificates/RSA/PEM/32k-rsa-example-cert.pem');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"RSA","n":"qzPFsFIf3cSes25DloV3y3d8gKMcZVE_EQ_6e_MZnyqDbuOEP39yQs3aunzbZRoO8Xw8lLoJNduiKKsco7odI753kBvz1eLyke-sWBVZttbnYyz9AE3ZXfAb9rHW2AxgIqHNsQOsLJS_douGZwxawNdE90WM4QG80bDpkxxHfObtmZIbZoOFSeokDHA5jokQGzJ65t6ARtQOIht84pIlAr8RO0vCUiJ0R4TdAffbdIukMcVfSoZBlZJ_q-yBtPoqB1Nmr1x1FqCtR81NrEtdp7CUHy4yLIskMzHTwJL24dx8zPS9RBIAuR6HO6soQwQgKY5NYmyaZGuWDrzw0Lor9_jjcx3x7NlXEUffGyUdT_bZ6owsgd-SpvnbqXPXIf-u5JH7afSUuajytHnGVilQOpEg06B0F-AumUEx8vdLPczCx0CED11mhRhT1eRQPJlzxgqA22SN1Yz0P55R8QbfFYcflpEtZbHmdvwMSipEoEUyI8aA9z268oNVnnAGhG3cOqk8-4HOvtqZ9LIc8jUcQLtWX-PJav9EePnWuV6pFwzvKcwl09m08xIfIh9DvFVJz3Fks-X6c1tVo2Valftlj8fnlzu9WgownkwhM4KN2UpcHcff4G-v9zckhcpROSzZ1ax5mPOUMF6B2OVawMhf3li9A9JEpBDxVu2-gZU6NbhvfH1f4PdNPUnlasPylHn4qz4S6_V1fuxho-2O_V72w3V5FDBi-m2D9vDVQvJtuoiJxUEyOWaxsenuzoFlq3jNHwm0SiabwVjaMyre4qktmHopLuLX2ixME3rbTtaXLAaly-t2X6oS4nFyhwP9f_WbJb4Yh_RDxksPj1hR_4nH43NTYjZBlLDM0YRb4xRzFmATQOUhPou6LSUbl8Tl2z7WYFzlcKgHwkWRaTGUV8Sz_h-_IfgZDvCtyyLhzvWOmfJBhsV1nTbDrr8DivZGH5huBNH88v_gbCVw36aAjH8BnmcHQ0ImUUwXoiB1iWSWB3x1xdYnAyQf5RV2PK86wVc4EBRxW6MeJHWZr-kFgHtcwk2ys8MewL8xlKs1S64APAWtD-WsLGEnUVMfM5EuWjoS9kB4BI4DC6M0uyDjaCuFu80wMmWfx9C3-Y2x7l5Lw0G4gRcUk-F3ONtKfsxMqAmV6aUVkXmdkX5LLa105CpIVqflM40CPl5mlVGEFlTf9u0zclyQ0_-qWt78ZzkpolPj9XKHikdYA_DKbvtfgtgNC07GIwBctoQsOrKGOxigeWzrAwfS9S5Wt7hvcs2R0Y04rXoeSTPbHWLumsJYLxC2HPtam3IxQJzCljIOFB5Sqi9WLO5l_yjmUGS2Fzy5DkuyFuC3o79rB-Vu0zpHQ5sHdbyYkfvi3QZx4jLuj2ki-3_1Qj7RfVdd1yWeudnFUy5QGfWh3-VoaK9UIZ1EeX62owXTGNOJovn9yMdwbXmy75qrkPXadFQG3lnuqq_Ucd8ZAYJvwfQb6uhTSv1kSFCpxyyaSBYjLU44QDF6FRh_QHLMBM2DVasOT0hsF2UWsIXUneoJHk_qVZSRmj5EDaIrWAUEZfL_geiwcW3_L3Y9iaHMkB93fHNsVEpLmTO-vLHZHYN0c-kKNVBw_40xGZ5ZgPJlT4JZVvBKuB2ka2OsSLcRXZvzZZZTnrRHb_9dngGkFpI0gc6gFu2d1mPIIFp6JS7AJ4_sYKE4yxuGG7IsA4ErnNBEK9Sr1XSu0_KfcIv63dm_AybDg1vmqMLCl5EiP9OIFsWdIM42970PH9h8Ri7KUn0D53RSRVkV38NW312A2JYCHfEfbIxyibEIrsusib98x6Bedh-3BpsWyih2XlDT6AFwJdD0cc_Uf56Vqv9waUtsSx-1xBwliZ35MKq-IfV6hcLnFgLhxsqakV8aFLAEzI8Ulned6zjRAC28aaDOZcFdKEMD0wHPUW8-9UTQxAgug8otEITWSkKubyXbdofpVa9Xwjq1-jLb4eylqey0RokKrHO6B7F3KtUF8Zsm0mGEg7nvUhjEBFL3AqkLke5Nb_78uqb3tzZF3iO6ghENar9s1DUIYqNkbMSeh7smgER_PBUB0MGMqRnx8qcr5t5yBEurZ7qq7-LYoJOoc6UwaPrQN_AFRou4ugiRrxIrvOwrDPr4y2zoi9XKnBBuYMnt2AkGVCNIA0WOKgmex4x_2Nri2JlRieAPwNPfW5PLkyPVRfw0dNzhg7csMl1Wctdw1JpHJhgMswuhYhRWGyzYWE4ZU8lvQWqA42MOKfUixAV4LmEzGz2eRQSPGWjLC85-mcxf_vssmD-mbuJAjzlLDzzwllrTDCQrt18DftpAAHhD5hG2HmQH9RDzcS3sniIx4p2zyqBHVQsWM74BlQjbODjgHRHerTgxYaNmh4KRA38lmb9omrUhI2Q0Lj5CF2of_Apd7fo8u6LpBpdEtirkn_7-9vPPiGerClV6lSjoNi_I_hHCneAq-3KZq7hM5XliJPvUrws_m0X5n6_fazdk-gOohEuF0Aq_1I5633sS-DGrFyan2K7oeoBGQN994-kweTR0lLko14nC5wnvizbsv7sDUNJTjM7LMYIrhKEILTjjGQ6WuCkYhQuM4RAnx74jFIchW8pS1tEnUcIOyBWgFB9M2zdbNmJg7vH43mmX408jMYVKs9CQz2Y7Vu33S0dSp9sWxM1KUREFVy1xTbVgKNxLxOzXiLOjm_b4EifAHZh_KTf0POm5RESU-TSrO29y5puTHL-PLuOE30jrxXaKhW5UzmQLUMhBGI7geYP6fE6QxyUi0gD_tLdMmzxTlZiOXkE6HnBQ-3Ar54uA-RFUhnzU-XT3wm--eINsvqyrHCyLQlmM71aBXnMlH5g0NJjdm42XSecTopWfFCfcNe1-ufpUuMGGg0C3LxVN5fkTmB2_6gai0AHh4dNhefGkKCZ5OcSNtA_UUI1nKr_wgPTI4X1catN9RE9mMYhOt-I5gOVRCihxDcUcBl2apUaFK-jHPs5rABqhykbi_dOS-zy42I86Vcu4B-_0GNlRIPRLZWFIhNRy_kfCOq4kb4SK9DjTvHsaq6YWMoL9Jk3JiqvH4yrMZ6T-XEFdJ8DGSc41lo1YJwhFUu0eGbGFKxyUBrHv1l9ByPrqWaiepnBBsda4y8G3SoiCfndwkbvLeE5ykYgurPpkYX_bau2PqsoAkiJ_GmbitKpXD71C5PmzvzLvpxkgC6hQq-v4L4WLelADvBpeikX9k23qhR5H3mkzNeMZgHyoFisy161cDgOlcg64g6C2UzJKlb5C1tOlQwM3fdm7cjBJXOjuxgi8Ewx6ov90eeaqIEfFvnUu1_IC_tFve9P_Us21Ak53vwStlHueYHtedJsHg84C5Ppt_z1LFR3Hh8m1pOnlb3kJw5eGpvsXweZrIIN0cvwz-NZ_orIxjPxLf23wy-y-lhObK17BfX1g-p759XtRSaG4Rj_QedauXHAA-SKgvwAOY3kBuWo9Oxx73JbC1kov55TkecHj2lXO_o49O5LCOa_h0nHIVb3JIGWot11sF_6zwNzFM2WtHFNu7Iu9hllumC8rvz3HEbylvSPQYzBQKy8NSyC6T9wbH6cAYY-vl59q1J4DwBH3DHKoMAec8InlnBO_ekJa8SMdQMZxov0BaxJc0W__29w2Sza0cBsMslfpRIWRWMb4jNpyvCyEVxrGf7AakOl0_9P3JCQ2o8cuf-BGg_z_iQ3aTMYVWi_pWuxnhh5NchjQU8C3dxvnEd0Te9mmDlvZh-N9GULo0tlzHz3WZniUp7mxVQ3nkeS31M0LIIF3SetSMjXrGJ_4bzAnb3EjH44eFuvgOiJ8ChXLCmHLtIpFa0WSC6YVpBxqfPrxke-DyB2Lvz_46MSQ4iKvCFhdYWxBtwXCZDN5Dt4XFpMknL_VnuVU8a5_rRqpEebv_VF1pBZsvfTK6UXFWAApFvL4ebApuLsFInG3uk89N2SbenTTiBGWZWZjsEFsvf3iSFZdQ2bgKSLmJIsuXV1mUPkzGEr8SsPLDKhGNZBevtka-CfnukEPn7a3K_O5sYcccEtYwx0VNiC6dWu7B_-pflffa1m4pbhdg6KfykDO9_jU_LE692dhWUzbv977zGUlOnmsEMeqmSTo9V5Hv0UsEDGEjoe9piKidoZ8JdAq1WIpSBfW9M2wtkZHbi2nlaBnKJuTaaNs_nWjbG4y73hEqEqRlQMKrLsJU7rsmy3h6x6-J_tXfkKpWu_Z_PhR-ca2RV4ldwUNejBhBomg-6bcSq1lHXGTpwc0wSDmIUfE2W6ZZysaFpmGpTDFjTDqfeeAwwbzShK7Uc-OnJVNiQ5w1KALJNjXURSfI61vyWRBMtFHaC7t6ixwDfv6pqEa0xeDe4xf4Z1qdX1Zfs4xpdAyzZWmslUsXIYDtiTXq6NYGjnCEPYqneVGOWhP6re0UfzeqqB6p6_L42UoqFrrjU7jnEWRlz6gxdU9qOJgLX3u6CIYtN6b44tpsqA23fNBiuf4SqoYimbd2YVjXFRFFNZ2XqJ-wBqYcD5xIfudMN6W5cAD4p5cTQ11_-EqIp8rDxiWOs-PN8SQTIE7ZYQ6na-lSITpchNybreE9SqhzluoY71DN8oQuUJHonrAW5Hh_VroGBxpbO9XdNhw0XrC-S9iH9DDEUedanM2DznPUZsHHutG8H0K9AEyWRS01sAwrF73ZG57qy5IciYMHZuFbkY0lzwbF-vd15jgNfP4JTmZD2sVWwVgI7Qp9T2hd0uuZL_huHl2baRCyC_DSI9c6p3q9Ud_tBN_yCcNcUVx0rS6EGfzM8VYOGwyiBVBAgVDjBXiKBsUVWA3ljfOtYhLKBDHkqhvoQaczSI2fKX7L7cwgXeBdckoaNhno6mCpZBamuyBZ1Iy6TnguQi59MCCKdiczIpfeumbSDEovy2IbQmPqld_JI6WOufgldiITu3hXR5KNazan2mc3NrKu1SEXZpdzb4wJZZ26U_1xE2GLMJru05yZoVNEkN72DhagM1R5oqHwPzRcn3ahdYvUzDoP6UHEpa76A23lqafY7F98l66hmAnXXlEKzEVwthYoxWANYtVsxs9NktNJdNMB3OCMnCo9BWkefmjlrzMJSkBP_1mfxN2o3W1tMNXpk5OQPO20_eWPF3iYhobSo8fcxzXtw9bg1BXr0TADj0hl_z4jw93wVGGLlsA3qYstay0I9yJgHBZmhxc7V1JzNWdwxIDmRgA5eCm1ELVBxpIup9WGZlUs1rzwqXzI-37i7l3dwFfCf_i2g8m-gNQjuM6YqkSz-XKcn-sJEg1XSMhoB15sgYE9U-2Oe-_EGLK0dOU2zyHO40F8ghvhKWpuAcITX_QnEMremwsiCl0PEnGZ98BXzlRvd1MFNc0ZUwzN-wTVxs4jNkteNbp0MjIKA5Y6FiCEX6koNWY9cLXSNg4XG4IsWRQrfIn2WWFz_nhzlaZNm_NUM1kmKRREPmsvQ","e":"AQAB","x5c":["MIIR2jCCEUMCAg4EMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\nA1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\nMRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\nYiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIx\nMDEwMTIxNzQ5WhcNMTcxMDA5MTIxNzQ5WjBKMQswCQYDVQQGDAJKUDEOMAwGA1UE\nCAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\nZS5jb20wghAiMA0GCSqGSIb3DQEBAQUAA4IQDwAwghAKAoIQAQCrM8WwUh\/dxJ6z\nbkOWhXfLd3yAoxxlUT8RD\/p78xmfKoNu44Q\/f3JCzdq6fNtlGg7xfDyUugk126Io\nqxyjuh0jvneQG\/PV4vKR76xYFVm21udjLP0ATdld8Bv2sdbYDGAioc2xA6wslL92\ni4ZnDFrA10T3RYzhAbzRsOmTHEd85u2Zkhtmg4VJ6iQMcDmOiRAbMnrm3oBG1A4i\nG3zikiUCvxE7S8JSInRHhN0B99t0i6QxxV9KhkGVkn+r7IG0+ioHU2avXHUWoK1H\nzU2sS12nsJQfLjIsiyQzMdPAkvbh3HzM9L1EEgC5Hoc7qyhDBCApjk1ibJpka5YO\nvPDQuiv3+ONzHfHs2VcRR98bJR1P9tnqjCyB35Km+dupc9ch\/67kkftp9JS5qPK0\necZWKVA6kSDToHQX4C6ZQTHy90s9zMLHQIQPXWaFGFPV5FA8mXPGCoDbZI3VjPQ\/\nnlHxBt8Vhx+WkS1lseZ2\/AxKKkSgRTIjxoD3Pbryg1WecAaEbdw6qTz7gc6+2pn0\nshzyNRxAu1Zf48lq\/0R4+da5XqkXDO8pzCXT2bTzEh8iH0O8VUnPcWSz5fpzW1Wj\nZVqV+2WPx+eXO71aCjCeTCEzgo3ZSlwdx9\/gb6\/3NySFylE5LNnVrHmY85QwXoHY\n5VrAyF\/eWL0D0kSkEPFW7b6BlTo1uG98fV\/g9009SeVqw\/KUefirPhLr9XV+7GGj\n7Y79XvbDdXkUMGL6bYP28NVC8m26iInFQTI5ZrGx6e7OgWWreM0fCbRKJpvBWNoz\nKt7iqS2Yeiku4tfaLEwTettO1pcsBqXL63ZfqhLicXKHA\/1\/9ZslvhiH9EPGSw+P\nWFH\/icfjc1NiNkGUsMzRhFvjFHMWYBNA5SE+i7otJRuXxOXbPtZgXOVwqAfCRZFp\nMZRXxLP+H78h+BkO8K3LIuHO9Y6Z8kGGxXWdNsOuvwOK9kYfmG4E0fzy\/+BsJXDf\npoCMfwGeZwdDQiZRTBeiIHWJZJYHfHXF1icDJB\/lFXY8rzrBVzgQFHFbox4kdZmv\n6QWAe1zCTbKzwx7AvzGUqzVLrgA8Ba0P5awsYSdRUx8zkS5aOhL2QHgEjgMLozS7\nIONoK4W7zTAyZZ\/H0Lf5jbHuXkvDQbiBFxST4Xc420p+zEyoCZXppRWReZ2Rfkst\nrXTkKkhWp+UzjQI+XmaVUYQWVN\/27TNyXJDT\/6pa3vxnOSmiU+P1coeKR1gD8Mpu\n+1+C2A0LTsYjAFy2hCw6soY7GKB5bOsDB9L1Lla3uG9yzZHRjTiteh5JM9sdYu6a\nwlgvELYc+1qbcjFAnMKWMg4UHlKqL1Ys7mX\/KOZQZLYXPLkOS7IW4Lejv2sH5W7T\nOkdDmwd1vJiR++LdBnHiMu6PaSL7f\/VCPtF9V13XJZ652cVTLlAZ9aHf5Whor1Qh\nnUR5frajBdMY04mi+f3Ix3BtebLvmquQ9dp0VAbeWe6qr9Rx3xkBgm\/B9Bvq6FNK\n\/WRIUKnHLJpIFiMtTjhAMXoVGH9AcswEzYNVqw5PSGwXZRawhdSd6gkeT+pVlJGa\nPkQNoitYBQRl8v+B6LBxbf8vdj2JocyQH3d8c2xUSkuZM768sdkdg3Rz6Qo1UHD\/\njTEZnlmA8mVPgllW8Eq4HaRrY6xItxFdm\/NlllOetEdv\/12eAaQWkjSBzqAW7Z3W\nY8ggWnolLsAnj+xgoTjLG4YbsiwDgSuc0EQr1KvVdK7T8p9wi\/rd2b8DJsODW+ao\nwsKXkSI\/04gWxZ0gzjb3vQ8f2HxGLspSfQPndFJFWRXfw1bfXYDYlgId8R9sjHKJ\nsQiuy6yJv3zHoF52H7cGmxbKKHZeUNPoAXAl0PRxz9R\/npWq\/3BpS2xLH7XEHCWJ\nnfkwqr4h9XqFwucWAuHGypqRXxoUsATMjxSWd53rONEALbxpoM5lwV0oQwPTAc9R\nbz71RNDECC6Dyi0QhNZKQq5vJdt2h+lVr1fCOrX6Mtvh7KWp7LRGiQqsc7oHsXcq\n1QXxmybSYYSDue9SGMQEUvcCqQuR7k1v\/vy6pve3NkXeI7qCEQ1qv2zUNQhio2Rs\nxJ6HuyaARH88FQHQwYypGfHypyvm3nIES6tnuqrv4tigk6hzpTBo+tA38AVGi7i6\nCJGvEiu87CsM+vjLbOiL1cqcEG5gye3YCQZUI0gDRY4qCZ7HjH\/Y2uLYmVGJ4A\/A\n099bk8uTI9VF\/DR03OGDtywyXVZy13DUmkcmGAyzC6FiFFYbLNhYThlTyW9BaoDj\nYw4p9SLEBXguYTMbPZ5FBI8ZaMsLzn6ZzF\/++yyYP6Zu4kCPOUsPPPCWWtMMJCu3\nXwN+2kAAeEPmEbYeZAf1EPNxLeyeIjHinbPKoEdVCxYzvgGVCNs4OOAdEd6tODFh\no2aHgpEDfyWZv2iatSEjZDQuPkIXah\/8Cl3t+jy7oukGl0S2KuSf\/v7288+IZ6sK\nVXqVKOg2L8j+EcKd4Cr7cpmruEzleWIk+9SvCz+bRfmfr99rN2T6A6iES4XQCr\/U\njnrfexL4MasXJqfYruh6gEZA333j6TB5NHSUuSjXicLnCe+LNuy\/uwNQ0lOMzssx\ngiuEoQgtOOMZDpa4KRiFC4zhECfHviMUhyFbylLW0SdRwg7IFaAUH0zbN1s2YmDu\n8fjeaZfjTyMxhUqz0JDPZjtW7fdLR1Kn2xbEzUpREQVXLXFNtWAo3EvE7NeIs6Ob\n9vgSJ8AdmH8pN\/Q86blERJT5NKs7b3Lmm5Mcv48u44TfSOvFdoqFblTOZAtQyEEY\njuB5g\/p8TpDHJSLSAP+0t0ybPFOVmI5eQToecFD7cCvni4D5EVSGfNT5dPfCb754\ng2y+rKscLItCWYzvVoFecyUfmDQ0mN2bjZdJ5xOilZ8UJ9w17X65+lS4wYaDQLcv\nFU3l+ROYHb\/qBqLQAeHh02F58aQoJnk5xI20D9RQjWcqv\/CA9MjhfVxq031ET2Yx\niE634jmA5VEKKHENxRwGXZqlRoUr6Mc+zmsAGqHKRuL905L7PLjYjzpVy7gH7\/QY\n2VEg9EtlYUiE1HL+R8I6riRvhIr0ONO8exqrphYygv0mTcmKq8fjKsxnpP5cQV0n\nwMZJzjWWjVgnCEVS7R4ZsYUrHJQGse\/WX0HI+upZqJ6mcEGx1rjLwbdKiIJ+d3CR\nu8t4TnKRiC6s+mRhf9tq7Y+qygCSIn8aZuK0qlcPvULk+bO\/Mu+nGSALqFCr6\/gv\nhYt6UAO8Gl6KRf2TbeqFHkfeaTM14xmAfKgWKzLXrVwOA6VyDriDoLZTMkqVvkLW\n06VDAzd92btyMElc6O7GCLwTDHqi\/3R55qogR8W+dS7X8gL+0W970\/9SzbUCTne\/\nBK2Ue55ge150mweDzgLk+m3\/PUsVHceHybWk6eVveQnDl4am+xfB5msgg3Ry\/DP4\n1n+isjGM\/Et\/bfDL7L6WE5srXsF9fWD6nvn1e1FJobhGP9B51q5ccAD5IqC\/AA5j\neQG5aj07HHvclsLWSi\/nlOR5wePaVc7+jj07ksI5r+HScchVvckgZai3XWwX\/rPA\n3MUzZa0cU27si72GWW6YLyu\/PccRvKW9I9BjMFArLw1LILpP3BsfpwBhj6+Xn2rU\nngPAEfcMcqgwB5zwieWcE796QlrxIx1AxnGi\/QFrElzRb\/\/b3DZLNrRwGwyyV+lE\nhZFYxviM2nK8LIRXGsZ\/sBqQ6XT\/0\/ckJDajxy5\/4EaD\/P+JDdpMxhVaL+la7GeG\nHk1yGNBTwLd3G+cR3RN72aYOW9mH430ZQujS2XMfPdZmeJSnubFVDeeR5LfUzQsg\ngXdJ61IyNesYn\/hvMCdvcSMfjh4W6+A6InwKFcsKYcu0ikVrRZILphWkHGp8+vGR\n74PIHYu\/P\/joxJDiIq8IWF1hbEG3BcJkM3kO3hcWkyScv9We5VTxrn+tGqkR5u\/9\nUXWkFmy99MrpRcVYACkW8vh5sCm4uwUicbe6Tz03ZJt6dNOIEZZlZmOwQWy9\/eJI\nVl1DZuApIuYkiy5dXWZQ+TMYSvxKw8sMqEY1kF6+2Rr4J+e6QQ+ftrcr87mxhxxw\nS1jDHRU2ILp1a7sH\/6l+V99rWbiluF2Dop\/KQM73+NT8sTr3Z2FZTNu\/3vvMZSU6\neawQx6qZJOj1Xke\/RSwQMYSOh72mIqJ2hnwl0CrVYilIF9b0zbC2RkduLaeVoGco\nm5Npo2z+daNsbjLveESoSpGVAwqsuwlTuuybLeHrHr4n+1d+Qqla79n8+FH5xrZF\nXiV3BQ16MGEGiaD7ptxKrWUdcZOnBzTBIOYhR8TZbplnKxoWmYalMMWNMOp954DD\nBvNKErtRz46clU2JDnDUoAsk2NdRFJ8jrW\/JZEEy0UdoLu3qLHAN+\/qmoRrTF4N7\njF\/hnWp1fVl+zjGl0DLNlaayVSxchgO2JNero1gaOcIQ9iqd5UY5aE\/qt7RR\/N6q\noHqnr8vjZSioWuuNTuOcRZGXPqDF1T2o4mAtfe7oIhi03pvji2myoDbd80GK5\/hK\nqhiKZt3ZhWNcVEUU1nZeon7AGphwPnEh+50w3pblwAPinlxNDXX\/4SoinysPGJY6\nz483xJBMgTtlhDqdr6VIhOlyE3Jut4T1KqHOW6hjvUM3yhC5QkeiesBbkeH9WugY\nHGls71d02HDResL5L2If0MMRR51qczYPOc9Rmwce60bwfQr0ATJZFLTWwDCsXvdk\nbnurLkhyJgwdm4VuRjSXPBsX693XmOA18\/glOZkPaxVbBWAjtCn1PaF3S65kv+G4\neXZtpELIL8NIj1zqner1R3+0E3\/IJw1xRXHStLoQZ\/MzxVg4bDKIFUECBUOMFeIo\nGxRVYDeWN861iEsoEMeSqG+hBpzNIjZ8pfsvtzCBd4F1ySho2GejqYKlkFqa7IFn\nUjLpOeC5CLn0wIIp2JzMil966ZtIMSi\/LYhtCY+qV38kjpY65+CV2IhO7eFdHko1\nrNqfaZzc2sq7VIRdml3NvjAllnbpT\/XETYYswmu7TnJmhU0SQ3vYOFqAzVHmiofA\n\/NFyfdqF1i9TMOg\/pQcSlrvoDbeWpp9jsX3yXrqGYCddeUQrMRXC2FijFYA1i1Wz\nGz02S00l00wHc4IycKj0FaR5+aOWvMwlKQE\/\/WZ\/E3ajdbW0w1emTk5A87bT95Y8\nXeJiGhtKjx9zHNe3D1uDUFevRMAOPSGX\/PiPD3fBUYYuWwDepiy1rLQj3ImAcFma\nHFztXUnM1Z3DEgOZGADl4KbUQtUHGki6n1YZmVSzWvPCpfMj7fuLuXd3AV8J\/+La\nDyb6A1CO4zpiqRLP5cpyf6wkSDVdIyGgHXmyBgT1T7Y5778QYsrR05TbPIc7jQXy\nCG+Epam4BwhNf9CcQyt6bCyIKXQ8ScZn3wFfOVG93UwU1zRlTDM37BNXGziM2S14\n1unQyMgoDljoWIIRfqSg1Zj1wtdI2DhcbgixZFCt8ifZZYXP+eHOVpk2b81QzWSY\npFEQ+ay9AgMBAAEwDQYJKoZIhvcNAQEFBQADgYEATPINk\/17H+RLz459iCVQAGes\n8kc5sxYj3CkMlWrGMiCxvsgu2kak6dCa0f3DfiVt54Fry7s0OklHiZmipoiF4RCt\nyJwUSAzRrZFAbkpDg8oIu4Ui\/Bt13kY7xON+u4m0IgkLZSE+8BSjMrfjVvVxe+qH\n5i7X\/ibUTDjgyfdA8XI="],"x5t":"KGApLybHWJmBwZGgBk07AlRD9nU","x5t#256":"YD12k6kc4xuh_5vEHMyyOFpGs6VqTyaKMlxg0Nt2crA"}', json_encode($result));
    }

    public function testCreateFromPrivateEC256KeyFileEncrypted()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/private.es256.encrypted.key', 'test');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"EC","crv":"P-256","d":"q_VkzNnxTG39jHB0qkwA_SeVXud7yCHT7kb7kZv-0xQ","x":"vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U","y":"oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE"}', json_encode($result));
    }

    public function testCreateFromPrivateEC384KeyFileEncrypted()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/private.es384.encrypted.key', 'test');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"EC","crv":"P-384","d":"pcSSXrbeZEOaBIs7IwqcU9M_OOM81XhZuOHoGgmS_2PdECwcdQcXzv7W8-lYL0cr","x":"6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ","y":"b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU"}', json_encode($result));
    }

    public function testCreateFromPrivateEC512KeyFileEncrypted()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/private.es512.encrypted.key', 'test');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"EC","crv":"P-521","d":"Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE","x":"AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS","y":"AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC"}', json_encode($result));
    }

    public function testCreateFromPublicEC256KeyFile()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/public.es256.key');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"EC","crv":"P-256","x":"vuYsP-QnrqAbM7Iyhzjt08hFSuzapyojCB_gFsBt65U","y":"oq-E2K-X0kPeqGuKnhlXkxc5fnxomRSC6KLby7Ij8AE"}', json_encode($result));
    }

    public function testCreateFromPublicEC384KeyFile()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/public.es384.key');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"EC","crv":"P-384","x":"6f-XZsg2Tvn0EoEapQ-ylMYNtsm8CPf0cb8HI2EkfY9Bqpt3QMzwlM7mVsFRmaMZ","y":"b8nOnRwmpmEnvA2U8ydS-dbnPv7bwYl-q1qNeh8Wpjor3VO-RTt4ce0Pn25oGGWU"}', json_encode($result));
    }

    public function testCreateFromPublicEC512KeyFile()
    {
        $result = JWKFactory::createFromKeyFile(__DIR__.'/../Keys/EC/public.es512.key');

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"EC","crv":"P-521","x":"AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS","y":"AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC"}', json_encode($result));
    }

    public function testCreateFromJKU()
    {
        $result = JWKFactory::createFromJKU('https://www.googleapis.com/oauth2/v3/certs');

        $this->assertInstanceOf(JWKSetInterface::class, $result);
        $this->assertTrue(0 !== $result->count());
    }

    public function testCreateFromJKUWithCache()
    {
        $url = 'https://www.googleapis.com/oauth2/v3/certs';
        $cache = new FilesystemAdapter();
        $cache_key = $this->getCacheKey($url);
        $cache->clear();

        $result = JWKFactory::createFromJKU($url, false, $cache);

        $this->assertInstanceOf(JWKSetInterface::class, $result);
        $this->assertTrue(0 !== $result->count());
        $this->assertTrue($cache->hasItem($cache_key));
    }

    public function testCreateFromX5U()
    {
        $result = JWKFactory::createFromX5U('https://www.googleapis.com/oauth2/v1/certs');

        $this->assertInstanceOf(JWKSetInterface::class, $result);
        $this->assertTrue(0 !== $result->count());
    }

    public function testCreateFromX5UWithCache()
    {
        $url = 'https://www.googleapis.com/oauth2/v1/certs';
        $cache = new FilesystemAdapter();
        $cache_key = $this->getCacheKey($url);
        $cache->clear();

        $result = JWKFactory::createFromX5U($url, false, $cache);

        $this->assertInstanceOf(JWKSetInterface::class, $result);
        $this->assertTrue(0 !== $result->count());
        $this->assertTrue($cache->hasItem($cache_key));
    }

    public function testCreateFromValues()
    {
        $result = JWKFactory::createFromValues([
            'kty' => 'EC',
            'crv' => 'P-521',
            'd' => 'Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE',
            'x' => 'AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS',
            'y' => 'AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC',
        ]);

        $this->assertInstanceOf(JWKInterface::class, $result);
        $this->assertEquals('{"kty":"EC","crv":"P-521","d":"Fp6KFKRiHIdR_7PP2VKxz6OkS_phyoQqwzv2I89-8zP7QScrx5r8GFLcN5mCCNJt3rN3SIgI4XoIQbNePlAj6vE","x":"AVpvo7TGpQk5P7ZLo0qkBpaT-fFDv6HQrWElBKMxcrJd_mRNapweATsVv83YON4lTIIRXzgGkmWeqbDr6RQO-1cS","y":"AIs-MoRmLaiPyG2xmPwQCHX2CGX_uCZiT3iOxTAJEZuUbeSA828K4WfAA4ODdGiB87YVShhPOkiQswV3LpbpPGhC"}', json_encode($result));
    }

    private function getCacheKey($url)
    {
        return sprintf('%s-%s', 'JWKFactory-Content', hash('sha512', $url));
    }
}
