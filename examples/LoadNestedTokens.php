<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

require_once __DIR__.'/../vendor/autoload.php';

use Jose\Checker\AudienceChecker;
use Jose\Factory\CheckerManagerFactory;
use Jose\Factory\JWKFactory;
use Jose\Loader;

/******************/
/*   INPUT DATA   */
/******************/

//Encryption key (private only)
$encryptionKey = JWKFactory::createFromValues(
    [
        'kty' => 'RSA',
        'n' => 'tMLkjnn1h99fKDRE1ovgSMHdh9eFxE9hU2LSV6lqiRdKYwslVv1ZOvw9Py1HAv8rfbYZvp-zYbnQthdDQH3FAE8bMb5gq28sMydAEShj9gtEyFBIBAEPrRmI7djtkq34Z3C6gfmXnIgEQZiVEJGsvk09TofZFxlLQ4_s7Bc2IbxLJ2xXEx4U4E1Z0t7KQ_9f8r1A9BvamIHCnezzWWxbGjSdWTx06ZRTal5h5_sJzpPG3vWeeHR7d2X9_2dSrXBE_07I8HMfkG-Unwmei6ENb01e0X_LEIqhNONyNx236jpVR90OvHLj7tor76dmM6rQ-BDzBOsjQA-DvemzaVS_7D2_ZX6N5DifLNn_GdMQiOabdSMyy8QwiY7EgfJwsv7wsJurf-U73wSNOetQFHB68djfhEmL2ySKETwRXY4qnlnJHEZ0ghhQY3iRUzfe4cgzB9hsEVcXyispqGlNQBGLbmdGYPUlSeTXJwo6sLuMgILG3x9psLmtc6MZVjOjSOv2EOcOsJl83rwEkNw-Wa60v1xmyprNIRbrl02LmB_j6Ez0V8CtwAWXGK3WtFKjtgr8vnRi4kT42L60yvApexRnBPe3z1P-iQnbttviUK0wCvVYRM_WgBsjyJs49YaUdZGFf_zNMtjaHBWwlOqvNnDip1YquUe6jWpcSiTqAD3tfsU',
        'e' => 'AQAB',
        'd' => 'rn30ZBUXD7JxCT5rtTARsipyz08dsgNu0C_1HOpODUiOZk28Hd0y5d3YwcPTaPEp6pB_CaTgZNYaw6xxHzBJm6LBfaNpbhRDdp3NGsMCu-Dk5Pmai0L6_v5HUFK4A4As6q3HXPCzikdC1I-WVghJ2Op24_f_eGzSWsX0z3MYrjg11DihVbMUM_J3YzftyPYciRZoPT0mJ1IbrJev0gLnbsSboCjcMx8b5vJ1UJrlPKUqtNAlyeGnzfqG1qXHCeX2tP44uuRm8-bCcUO36NHvRiJKBbJ3M-Ce_Y8SEmJ9x33IFTcvonrFzSyOfSn7XqTmVJEIBxd1T8GqSwnuRx-oo6SOhO-fzA7x6uvTlhKziM-FIYzR-MJu5P4LltWfTkL6-x93yrt7onspgJMOpJ75_i1ZBrEIX3Pa-iP6UMymolcqeRayUxvaNBzV6ImNvXDFjOODBEX0O0lQJcrOP5SRNO4kR2gN_6Z7kLqJU0HOKJDagHfx637KJj8rZHPzlQkc3C7UA4JbTJrXuJ5019byI_FXzmXTJdvBWul5ybd7mK12DjzkpEf61pcsB1T_kE6-1uvb_fPLgHO5tSm9ML06s71mUKEEW0rbGoDt169A-f3CevfV5quQnZyGzyOXirtda2_849PKJO9MyxF7QRQOnJwIJDalgUuluMSDMhIoKAE',
        'p' => '4u-d5vDC92z1qREotxXJmu8CyN98bWiDaKRFwhnKJpAUvC3C7Y9MirXWFhfMdpnczbTaSjUfKEyKNyEoTF5XPR1MpDjySEgWM1L-0WFGkNbm0xPI7B7Q6j8Z26C_JtlE9CpgFusfq7QaZHCTkdKMSme8LaiR3EQhNCA3l8Z8lnPXY-VNcixDV9Pof6xij5z57ujyu55QZ7UIxUlJ1ynKdfz0jCpWI5G9vGLSBhucnq6h1-uttOqTzmhSoz6vqO8VMJYG72ENLm-pFwz3blpK6HiS_mlIVb-RK1FyW2yYKzZjWnlC59WVbeAxR6DjKnZR2rc7ikuFsv9W8TdW6tAXEQ',
        'q' => 'y-lhTagGQuNAhgKF3epR_pI4hy3db3uYa1Xje98dzAnb3PRPFSv_ad2faWxelOIhL5a01XPuoX2yiChSfk3V8okKzjZ41e9gFSmW9b62BsoTIP29DR-Ob1tH324MPFXtXoxQEMVVpg5_Bs0JTl23PB1JMtAgnDDYKHWsZu8FEEoBREs9QJHwPyOAIVbT-3Fl-ukw1yX2b1iFS3HhUFhqlxGPzV0Uf5zdAcH4025wYcFViwmeKXZL7ygtT_Nc_PfNn-u6ozP3EbeGNbbRrp0gRAzqbYWyhVRhuhVvDkCrNfoCjXJJev8d7OO0tECfGACpN_fT_BEu4c6fo9oQcOu0dQ',
        'dp' => '2QMJPcH4v4ErvpxREhu8qfNr90l4BGwQVe3ZY48j-BKKMZWVNXV2XaMbcg8aEER8mR4cLSB1hiUDe0qy7ay9wgyVsOlgD20YBcaVNQbP40wOecUOu3WQlKD5CkTC5tSYkuE--EuqApl9L5VUGPt9-t0OX582tKtWETHJ19MQaxOl4rpxgAAB-igDyqu_qNQVUbjj_jSbcUD2fSrjeOVW3dOiy7LkoqkJBvB9JSgccsZOsFuIxlwYMici90bH1kWjPs4JHbryTviqeweESbwArCQ5dR6a9Jz3prQBJppHPfOJuQgCyg4-Ek908KlS8tUo232ja1FjLlPtAUjJTkzl8Q',
        'dq' => 'grKFsZae3MR4GO0JDKIiB_-Ex_A33DrmCPY2JrFtkdhH2imlfraCsUJh6NqTDO6bwrrgEWiLbWr5wZfGuDn_hcMc7-uuK8GQXkAYCE9CsLtY425_fCfbzbg-KxGIOiwBRva8YuN48ESeWqeU7WvYBGno_u6z2Cjeg6BY7mkJX9VvVmy7R-XCjVWdzMCwgpu-d8J7kYs9l0Svuxm1ByCEwWt6NnEQsHLEnVnMuQgydBXNVJ7Hh1_Rb-rakEI2OdZDL9uR9wVZuTtehJM3dqozgiqdH7HwKNFbCkCuu_3rP1-Nv0efnXxjm_CfZGF_F41k6QCqGQiSeh1L6WPd4eLR-Q',
        'qi' => 'rZkWoYTTyWEzkq_0BNcdK0w2jMuHW8eCTX7JrwzbTJMK_ZFowWgcI8sgmqP6RLl8bozsGiv9WbtGtPC97NiomlwXbCQahZYbvw1ZdGQye4Y5uynkJODuDNRXKZggYyoH2T4nk3RGHjtAbQMFqqmagc4Vtkh5NdiZZ7H_PjzvIVkj_pWMV9bHTY_gga82BS3poHpXzIJ8Kc_SXVpEs4qaHGrG3oO5TtL-DObsmN438da_CHmnAfuhPeC8JgyCKPvuIDdgxNpDNxQFHeY-qipvITOWN4kaowvgK7zYdCJp1rtQooBaLKOX6ltxLCuSynWkl_-c8ZBnhNosu_bqZbsJfA',
        'use' => 'enc',
        'alg' => 'RSA-OAEP-256',
    ]
);

//Signature key (public or private)
$signatureKey = JWKFactory::createFromValues(
    [
        'kty' => 'RSA',
        'n' => '3GYAWUYofHpVYJdCIN7IZJRKuGyktsWTN3f_YFQZ9cnl6WCyFYVRG9Ql17TL1sxAwIJIdSrAGyOKvZF4lBKYrYDOAP7P0S9OQfv6K1C-cMGE1NJL29VfOC7xObDlVHNo3DshYTBNnQz3bND7LXnnU5H-M4gI3nzL8qtPYIrtbU-pKuWzZxeCtWbuzgp3sP3pEsb-akx71rl9bIlo4GJ_AaQSD-ASUstVeqF_R8j-gEAZerT9R-Mze5ZnCsaqBSD6B5aexYBXxah0zr0cHseujHU4Gi0MvkXSC7tt0lRg6K6e4IPXUviXeF6utiDLFkaLLP42PmAzle_uMMbgA9yX3o6-09l_poDlb9oeoOZG2K-5rwazUH8qRrAHzHLFgarqd9glh1gtkrpXWT5Pv6JbgWAgSn0VHzunp-lDSG0MqzyS4k77jlkahDgTEpsrcUPl6NDlWyboXFI5LR6ISn3BAD0fCIDhGrtpvzIYK05FqyPfINEzAlt_O7vp03m1_lGZt2mPW-W-Bvlp0b6jFlWW00rO_JR-fx1YNNnxTRmJ2qnzssBlV5XdoCkJC0YHJ4u1AUhaOLNZ3iTpCYZHzMgmG5Yv12sDPoPaUKA_v3gExzPejJccZx0-IoAatEGDBhT3213i3XNyiiJZsthAaHuL5JtKGzeQ87UFBH0Fd0dS6Xc',
        'e' => 'AQAB',
        'use' => 'sig',
    ]
);

//The JWE
$input = 'eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiemlwIjoiREVGIn0.HTqRAw07e-U4IPYIyhnleMUeK9tftwfvozmaam17a6TPBf_4eX-la1Yn6n-Hb5K1FA-EhXAcbeKh0pZvTdcQrnLx73HOq9XFqqSfZ9cIbbVQQwCbjlZ1qTZ0U0jEiOSYpp13ICqEWZhQK-_JpK4MTTVoky3Xor3Jat2Xr3BNEbdsnlrBbHhECOPwzqKre-Xmc0XQS0qhBfCIJ7zOVy0O8PRyHjE3QFlW8vu-rVylbO-mVCP9GLy-kWV06vEsrFm1pW1on7CWVMSoPXDvd4P8pDpOfVvPWngGxl4q1CLliIXk-7guMopsuX5UkVmbEI7Ul-RV4r6q8JSN5x2mBJHw-GnZohn4mIpMykegMhamHwl3s9v03npCob_y9XookH34tOLETvNxxrY_MW01-vVQdVTqr29gD8uzPsSLSvYHClNW6SVY9YMPOZ7polmyPqTh3yejFGLZqFla4dJQT4aRTnAVWxfsnxrxxZHJAHyAwS-gsUMUU10-gufpMS63z2pWickHG241od9UgKhutSwLClqXNFqLdhbQ8B0N6FfKLX5syU4t8PYdWyTtqDiaAEevajk_b6BWUluLAQzerT3G7dpnc63HJarpcoll-ySVCZ5GMBK8wz_cM8h6GhhmHobVDS1P6Km8qc5wXZ0UACYnZAfejyFYoe1hTNVLr8ZDoyc.MY6DO3inlO3-W6NWvz-LKw.zYN__XJ75TVYNF-wIuQYl2dhRzGGX8lT8FHCvrMgKjcQS5Fm9Dj7bE-KFyzKWshWt-_SH4OzHwceugNEz8ejLPjty54h5_tM63cEx2idFM5haEtp3P8rjMEe85kIB6B0-m-mqMdLIvmr-rBaiVg9FBW0FgVaUdAbRnWJ4v7VjvjhOHCPE2dwMJtjqRE2yvllq-vdfECBT_WUUsEz6eQFPmRCsOHU5h25AN6PpQ8oYN4JHAVeNHSlNN0hVoKcawKYXZ46yjtJ538DCyKIci5HZZorDMnyhTeeWkeKLYL-JA3N7714nUXu_YXwkX5Vl9Zli-6FJGM2BsHzG0DsgtldRj5s5deYpz3knAmdh8ylE5Lq8AGriI65KpYztT___vv3vUNitytcP45JPAbvKGegw0fyMO4-dpvDh9k2l9Xp-XMEkWc124w95pqqC06rTMLftzbNPL84hVqGyqwqDTV7DCwFrwrVIsvbLyXcXDco2dAJjbjQ10CGn0UXaaeTjjn6L32InhIqVU-5VfvxWMmserE8fKHMABb04Q1OY9bFl_bkkHBfuqhuys0B8_MTEeaNyg8Budat8w4lxzpAv1URggmCusBLtHBPvkfCZVH0DJlGUsp9KThbz3H1M_vtnfEpkvk7mhX5ZV91Pntx-CTrXVBx1OM5DQOG4yZCD5YToXr3knyTgi5iDglxEgfVYKtyzgB_F4knyGXVOEiR1aKiyGEmXnRAUuKlhr41tXVKFdPzsrAr-ayZg4qU3HQ5rXDhFhKwg8VQJVq9IimfOToGk6xkDdZxMrI9Z5hxyOxUA_IHXjAiG29mfTkxIjt0J8y1j9QInOrwVNmbcIPTUy6EqB0UmTs5wL6_-xCb10O4AOQVGU0HUjbemZBOabIIAw-iH7TS1mOM9_84hqvQ2ZOdbA.C5jSR70i1wDmZs5y3JxLpAoWejfBnTDWNcEETD1-S-0';

/******************/
/*    LET'S GO!   */
/******************/

// We load the input and we try to decrypt it.
// The first argument is our input
// The second argument is our private key
// The third argument is a list of allowed algorithms.
$loader = new Loader();
$jwe = $loader->loadAndDecryptUsingKey(
    $input,
    $encryptionKey,
    ['RSA-OAEP-256'],
    ['A256CBC-HS512']
);

// The payload is a JWS.
$jws = $jwe->getPayload();

// We load it and verify the signature
$signature = null;
$result = $loader->loadAndVerifySignatureUsingKey(
    $jws,
    $signatureKey,
    ['RS256'],
    $signature
);

// We check the claims and the headers
$checker = CheckerManagerFactory::createClaimCheckerManager(
    ['exp', 'iat', 'nbf'],
    ['crit']
);
$checker->addClaimChecker(new AudienceChecker('You'));
$checker->checkJWS($result, $signature);

$claims = $result->getClaims();

//Now the claims are verified and can be used.
