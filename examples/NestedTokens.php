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

use Jose\Factory\JWEFactory;
use Jose\Factory\JWKFactory;
use Jose\Factory\JWSFactory;

//Encryption key (public or private)
$encryptionKey = JWKFactory::createFromValues(
    [
        'kty' => 'RSA',
        'n' => 'tMLkjnn1h99fKDRE1ovgSMHdh9eFxE9hU2LSV6lqiRdKYwslVv1ZOvw9Py1HAv8rfbYZvp-zYbnQthdDQH3FAE8bMb5gq28sMydAEShj9gtEyFBIBAEPrRmI7djtkq34Z3C6gfmXnIgEQZiVEJGsvk09TofZFxlLQ4_s7Bc2IbxLJ2xXEx4U4E1Z0t7KQ_9f8r1A9BvamIHCnezzWWxbGjSdWTx06ZRTal5h5_sJzpPG3vWeeHR7d2X9_2dSrXBE_07I8HMfkG-Unwmei6ENb01e0X_LEIqhNONyNx236jpVR90OvHLj7tor76dmM6rQ-BDzBOsjQA-DvemzaVS_7D2_ZX6N5DifLNn_GdMQiOabdSMyy8QwiY7EgfJwsv7wsJurf-U73wSNOetQFHB68djfhEmL2ySKETwRXY4qnlnJHEZ0ghhQY3iRUzfe4cgzB9hsEVcXyispqGlNQBGLbmdGYPUlSeTXJwo6sLuMgILG3x9psLmtc6MZVjOjSOv2EOcOsJl83rwEkNw-Wa60v1xmyprNIRbrl02LmB_j6Ez0V8CtwAWXGK3WtFKjtgr8vnRi4kT42L60yvApexRnBPe3z1P-iQnbttviUK0wCvVYRM_WgBsjyJs49YaUdZGFf_zNMtjaHBWwlOqvNnDip1YquUe6jWpcSiTqAD3tfsU',
        'e' => 'AQAB',
        'use' => 'enc',
        'alg' => 'RSA-OAEP-256',
    ]
);

//Signature key (private only)
$signatureKey = JWKFactory::createFromValues(
    [
        'kty' => 'RSA',
        'n' => '3GYAWUYofHpVYJdCIN7IZJRKuGyktsWTN3f_YFQZ9cnl6WCyFYVRG9Ql17TL1sxAwIJIdSrAGyOKvZF4lBKYrYDOAP7P0S9OQfv6K1C-cMGE1NJL29VfOC7xObDlVHNo3DshYTBNnQz3bND7LXnnU5H-M4gI3nzL8qtPYIrtbU-pKuWzZxeCtWbuzgp3sP3pEsb-akx71rl9bIlo4GJ_AaQSD-ASUstVeqF_R8j-gEAZerT9R-Mze5ZnCsaqBSD6B5aexYBXxah0zr0cHseujHU4Gi0MvkXSC7tt0lRg6K6e4IPXUviXeF6utiDLFkaLLP42PmAzle_uMMbgA9yX3o6-09l_poDlb9oeoOZG2K-5rwazUH8qRrAHzHLFgarqd9glh1gtkrpXWT5Pv6JbgWAgSn0VHzunp-lDSG0MqzyS4k77jlkahDgTEpsrcUPl6NDlWyboXFI5LR6ISn3BAD0fCIDhGrtpvzIYK05FqyPfINEzAlt_O7vp03m1_lGZt2mPW-W-Bvlp0b6jFlWW00rO_JR-fx1YNNnxTRmJ2qnzssBlV5XdoCkJC0YHJ4u1AUhaOLNZ3iTpCYZHzMgmG5Yv12sDPoPaUKA_v3gExzPejJccZx0-IoAatEGDBhT3213i3XNyiiJZsthAaHuL5JtKGzeQ87UFBH0Fd0dS6Xc',
        'e' => 'AQAB',
        'd' => 'LHR6j4dCNVFrlS8NTJoDK55pr-diFeemOSMAJMrx7YzKzhcN9J9Oa-GPvIGgN_Q8_1eIC_ISi6bQnkoQWzWhDCYV50d-XYBANbkAjeocb5vpEhBU8sOIEEoPqAZRS4Z32SwoIHVgwlPSOGWytEqJaWbiMjy3JUFg1dLOEPgUyd6ujZOFaz7nw3U-p9qep9mfQIVY3dINjJMfhFv3BoN3gLo6Vm9o4sBWvoSCqtUU2IOVYBXPnMdsI_qDUD4gHya2p_8uiUHI8np3DRhB6sd2IqimJ0l874gfxPQKQ8l3PpeyPjD5pqezzbizXtMgg565BdtEz7IR1aVukvIaT00YaJDGScHIBVOenbgcLk9xDwZv3rPQfeUAeLK796mcxh7tyoVmkyu2ctvPBvb6FD9K-aPbf5yADLWmRn8ENvJ91kP5Aw4X5neNC_OyjIXoUisqIFcIdRDbE05-qS784TcT1HwYmHekKNQZcBXp4UFYVHbpe906vPHnl8jTbdrx_rnQ2Bdgj3bGi1-AbexBrdHWibTNa8etj191jy8AUgS-hvY1mNiSHz5NIgcWqXpBlh1tOyzQq5443r6brMumozWG2HGum88h2rHx9rdPqLGbdPjkjIU2XEmxY3RwtzukhjDE4-NojHMkqJU1cn8FhDbVPp7-LWPi6d73RSOjS9K8iaE',
        'p' => '-pnJRadMaAz8OE757V7DEpuBoHvzIn4eUwJy9ROivlrlcLW4mXmGzchYw802lc8_3faTgEcbSJsfeBGHmyPzoWNvNQANXdyqntIuYklpjTKfJlDZ-OcsAZUf0moR2O__toO-fCKT3wC2kHELgy5ilV2SfDmw4lwwfc4wI7uV4DDeVI2Hz_TNkSja1-4fZZqEGodTOs9Yg3YNadLYV9sxAN-efDwt1_u5ibrBfP1L0RKlCt_f1MTWcAPaEJo2INC-c6ibfJeLulseZQWHZEj4Grh3fZ1O8BDQ7bqdNYaou0Q1E0M43_vkCOKvXvNKJRGWcnLw7UQlpokRHGNThMKWUQ',
        'q' => '4SWhoahNejMn4JkNGMubdl5QptFUnkwHxCvIlTdT1753wKx4bMDlAz0MkBoq027cCJSCcomhOh9pfVK3BsNiV1I_-RmHnX_5sXOMgSQHOFm1vshnW9Jvl546nuggvzYj3sxQJyo7VAx12WiMlmdnjpqZw3IU5y8OkMIYdF3NDanNtbucNR7C4tNOOpbKcY6XDKnMJjPdjUv6JjVTt4EofnFiQAlULxbSa1BeaWhbhoNwv3dHZ0Ik3NbdtY7vSff2O5ZArlhMA-lZIeihNdWX5e9OpAso1It5PJ5-ano_TtX5Dmfy5frsohx7oZUY_GqrCNoGIe9tK6WQ-vP9uXRpRw',
        'dp' => 'KrY_adHD4hAkhOxhCKYYFXnPtCysGfro7DkEouS_3jXb2UP_vJjL8xLsniLB5PK37fry1PBJpCxcRrimJjkQczdhYuUpYhAUPJGSOkpM5TX1jjBFlnjANVzXWaOeex0ctlzqAHpcPav_ccryrV8giliyeN3UWiBgW3DjH5P_TYDGxB6DQVx2FQGjmx4I1-ZoEaVy-BkS-wUJ8DlxijffuEhk2MPhBGjxDJp6E_WQEIhe_OV_XuJVsi3V4vKFuz4Y19mq9qdVt2OEYK96jgspzlQWeaBwLdaP5ZTi6paS96f-a9QPQ43JJgKM5WAOCRdgTw1sJuRwjlvaQL5lI8GOoQ',
        'dq' => 'bsuxBbeoIPmppxpKWqhf4dk6AU3EQX4S2FPfiqbGiMX_cn6taH9oc7aIRyXJa3EDsOk8ZJccE1k_9V9OGHLwIx6jwrbwiO5gdxXwz-Bl-TIUgUVnr8UYC1nfaTG8Y7yF3G9ZBlz_AzZ6jDmp7Z4HVSL5hjfO15HNrikGFcXPUej9BXDEx1NS_oKT3bs09rr_1Eh-4VHmtlDsUf8uKoDR559uhSrSFbY6aHsNavvjBogKZP6S0dq3_0Fxq5YiZZkzwFEJlYJ4LfiYV1p-ctqgvJOOdKXVOvtD9zPb7BQqsWYVASTgYJKh_ojbwkF4IUdw0ZNRL0P-ylrYxNZrRudlow',
        'qi' => 'aWrkSUY5nItXhxOkRnamDzmceOYiErnsbEgUv8hs-VI63I8zZLGOzy4cDaXBWRao5nyjuCCYK_Q2o_d6z6f6qH_Mz_R1DZn9RFQOVdtZdhGU9-U2pnXygBTxyYKCjJCS5iJJ9thm29qp7xcsJXwjIA-eP-VvddM0iAGyhTJQZBsV5auFBX5oazYLT2b6Ye5G0HfaCfdmLVQsWZcvxeao7PwgNTbuikUE78Byf3vOYenDhV323-e8sOJ_ExLheNSQMGTgvG5duvVo3bwOQMY8Wh1oI1D43zJnJj1cGLD9UBZ6XDiQqlB4bzNfjUSCGStVRRLVw4IhFun96DuWkS0z3g',
        'use' => 'sig',
    ]
);

//Claims
$claims = [
    'nbf' => time(),
    'iat' => time(),
    'exp' => time() + 3600,
    'iss' => 'Me',
    'aud' => 'You',
    'sub' => 'My friend',
];

//JWS creation
$jws = JWSFactory::createJWSToCompactJSON(
    $claims,
    $signatureKey,
    [
        'crit' => ['exp', 'aud'],
        'alg' => 'RS256',
    ]
);

//JWE creation with JWS as payload
$jwe = JWEFactory::createJWEToCompactJSON(
    $jws,
    $encryptionKey,
    [
        'alg' => 'RSA-OAEP-256',
        'enc' => 'A256CBC-HS512',
        'zip' => 'DEF',
    ]
);
