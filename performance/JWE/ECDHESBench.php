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
 * @Groups({"JWE", "ECDHES"})
 */
final class ECDHESBench extends EncryptionBench
{
    /**
     * @return array
     */
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES', 'enc' => 'A128CBC-HS256'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES', 'enc' => 'A192CBC-HS384'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES', 'enc' => 'A256CBC-HS512'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES', 'enc' => 'A128GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES', 'enc' => 'A192GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES', 'enc' => 'A256GCM'],
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
                'input' => '{"ciphertext":"j1vyDDB1LcCLZUrkKIHS1fgkRL_dcc8NmtUbd_4BgyMOVY9kjB9cxUZ2zHDal16iK7bDixop7q02UGCWZwsm30fy2xwUBS7JWeQ2TmH45IHrWmAF43dfjCiYLDkyA6-2hQ2jbKNg3YWaGSt9RprNJJGKbiyd9yM_hptaZHcyzNnp5bgVOneGgsSrDYhMvy1fnyEfWRhcIzpMXXKwIuthiOdGX3VhruMMNdMIK7cKiaQ","iv":"CDfk8arhCpFgbYIaQVvGyQ","tag":"ZAP3QTW026_Xir7pB4fUMw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJycG5OWmJwRGpTOGRJckhsVXlIUjNDZzJXTmlxbThTaGdmY0xzLVNxRU1NIiwieSI6ImNOZnhZQjd2N3RreGlucENreDVqTW03azJ0TF9lWG5fOW5NZkFHZDZvaGcifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}',
            ],[
                'input' => '{"ciphertext":"QdYb2vE-XGsK9HId22aV7ZgoQivDc7WjvXYFdnW5YfN_CqNiXKEPlVj-vX-VMCHIjw1ENKcdDsOzsnO_yPQ6yJD-OaVwUKUAMpsDitW7BE7_Rhcu0u6VYDPtUbY3V6QEhZHvVcjY3GraU_wiH8VsmRXk92ZqnAB6ns2RqjE_w6jUQ_HcvVMgSQzGEiRchG3m-C7J7ZQobqSFBjx6F0rKY3wPmfcVjwLp3V_SwfCfqFE","iv":"I9JZmj-rFyFXSdH-4TGAiw","tag":"fg3_3YPnx7k6AQeL7g4pj7vQu9zDsWxP","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJXWE43cUppR0NzRWVKT1NiV1FhU2QtWWVLYy13TXhBcGIxWG9BZWRuWktrIiwieSI6InRCaTloUDR0NEJYUEdabndWRUo2a25ESU9mMS1kUWswNHd3RC1hNThNVmMifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}',
            ],[
                'input' => '{"ciphertext":"4nvf9hLLqkkOS8k7dpKMZt_TlNbakTUGx53s7qJSpf16mDrv7-mJT5Rskb-Tolc5d5fjwY6-WmLj8hhTJiMt9SK0eVGcmVzGs37oPwFwCSoAfiS47FF9pHbP7VJtkM0yJ83IUu2fCEI1wpngLitWBQgV_5GRJYh2ZMAyK4IgIKZBdEV2bFtUwZ20RP7TqbXupvWvTBG6nATdAYC2ynGvJPFIrjMA88pu_4K6fQf2pUE","iv":"tffPrs8jhduM42DhyuteDw","tag":"reVeyf7ucrPEbO8vkzjdsIZIlb1Ex6kjx04OTFaztQA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJoRk9EVUhiOEtJUUJwYWg2UHY5UVVRdUV5dU5MWWN6dEdvRjNheTUxcHcwIiwieSI6InRQTTZBWXhxa3RndzdQMDN0OXVTNG5SbTVxcGl3YVhxSDE5cG9teS1LbVUifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}',
            ],[
                'input' => '{"ciphertext":"devVFkJBWsZyJZh8NIvCNJNNllG6vP4TU57DWJHjT3cbWWLrjiZmFRsAmhVLakFt2NsUXuvcZ90MZQPWJ1B7askn0MEWuyvhE_vrq6pe2JgrTkum92u1WTSIHJAnEnaNKt-lXGsokdZ9wDni9KM3krgYHjUEBnoVA83cTSCipQjllONKqJIB4nmAPfcUB4VPMSj38vPv_h9g7N5F9XA_e-gph3ZmVmw","iv":"KFat-JiJSDdZNgb9","tag":"AKxl8uyE7-18vWt7PqzuzQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJJSVBLY1dvSVp2NDl6RDZuamVDWGxkdWJndlhlN0FZZXNxR3gwSzJzZS1BIiwieSI6IlBKVDA5MGFCYVBvMVVWR1l5SWVoejYxWUt5MEMtYmlRVzBYOTFPMzRRMVkifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}',
            ],[
                'input' => '{"ciphertext":"qsPiw3M-kuEiLq9k1YDJNsOgfUK7HmX1UICfXc5d0v69AVNHAn9bvN7ir1A1R8rEygE8OpNcT-ys8E6ffRK92BRmbeyHExYo15ca27vVw_wgeC2J7xnCO8pKbhzaAUhRPH8_3QJliNRV5eZUBSMJ1kv2a6Su09lu2yztNKJ3vN5HERme4Yrlhb8nN6QuqTt40rt413J45AGcBl9nNuQJsX2hfaRZtMk","iv":"R6aepj4CWIneRlrl","tag":"otkuoD1RmuIdrRJel_Hznw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI4SFU5bjh4MTVzb0NiYlBtYl9yNkRkZ1lUQk9GOFBkSXRLWkk5YmVJejVNIiwieSI6IlVhajlwV1AtakhwODVXTTlaMzBZZGRUYjNTSkM1WUdWNDJ1Wi0tc3R6VE0ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}',
            ],[
                'input' => '{"ciphertext":"MpnYpNWSq2y0jMsgYObeZ8xDQ2PmUqg3XgGoMCRVyiAeW4FpX-u4xs8n09JJj6Opg77Qt_Spsrsqm6EBBOk6pa88aQXQFI4s6-Gxf5MCZ8ZLcOP4V_kMKrgzaiYWoff7hIsaHX-pmlcENHsH939hKRZG6d8OJuoIMKUld5dYWDDf3pkBGAi4i4T5P_bo2tSuu_tmWKApa3AhRu4nra2Rx6fS8oqzWKs","iv":"vK241oaasYXoV7kI","tag":"cDyRVa0FQUe2VgmwHzWpKg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJVUXhpNEpjS1A3eUY2OHppaEtsZFVPTmdQS1VhT2wyLUtUNUczdHF6ckhFIiwieSI6IlpjUFRYaTlhYjFPaWExUHRONmZqdUdhSDhEdG5SdkNfazZFQzhMdjlnc3cifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}',
            ],[
                'input' => '{"ciphertext":"zsLImwfWi4LZL5yv8_5r5I3IGFViEwaRFPNXTCDLyclMxz8zOifM2irbSeN83csSZr7a97D88LoFxbfF87LOGwtIAol8V2WeNtbnF-9i_hXx-waSkquK_yjuUUu7n-mXEejP7ce_m3lr_dhloygBU7bYpOnSpkJJ8fe13CQOO8pJ-eEXnNE3NRhRiNKSG8yHRHWkNGvEgdq8KQB-7QWmldhpJFPfNh3vzsALOi_5IPg","iv":"a0XAbhb0LDA6Ko9mU-4ijw","tag":"IhuMeLdR5r1VwZ0YqsBGDw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJPTEJhLWt4S0N5dllvRFdvRk9YZ043ZFcwenQyZnd3QVZtWExpcVI3dUh3eDZqOUc5RnA0aXprX2JpcXh6NTRTIiwieSI6Ik5QZ2VmSlNiX3VpYjFHZ0dhNjVGcHBhSWc4amExV1RkWjh1clBieFZtc3l4UmJwdmFWNnJ5RTBpa3luTkJCLUMifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}',
            ],[
                'input' => '{"ciphertext":"GDmN_KhQL11TBeuyJZCIRYlF1CFiutxh5FzPGeBktmLbzqEBtrnFgl4dy5hgEvCJFAITDTsZvRVsHiqk64ISlH0QyTsI_QarK9qB03YX5lQD58K0ZibwdaCzbfpKKoGu1b711mKJTSqsY5_Rq7cUWOv4HMpz7Y3hWl-PEGIacc4FKh9cl5f0FN-a5LMu1uFR2RF0NJdzcQtTIYx0sR1RcrHK6RDGDNjJMt0e4AiV4ag","iv":"2dSN8l9KOqcHC9BMnMjZxg","tag":"TwW0yUTxtkccqHHxeY_9ymPe09msNV90","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJyX3ZPRnlSZHI4NHFTdk9IZ21BbVFxekxFY0FtaE9WQ2U2eXdCbEJ1UmpvZ0tWTU9HcExYTlBBNFVBUzBzZHZBIiwieSI6InBkU041NDBVLVY3WV9GWUxjckhpS0tNNjFPOXI2VzQtUXM0Y19nUGRwNF9BSllOQWVGZTRCUVJ5N2NlTTJaNFEifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}',
            ],[
                'input' => '{"ciphertext":"mz6TqYIWF-ZBst959dc7XeWuaJTylavbCkuUQo98mBrUSrwzIb7joDVwkcd6rJKfi5chxyuMvMuGvRaaPfiBDIopQEVj_wuGilkjK_QC0J96itLqVYwVHpykMkO8uFGL5WwoTqt4rbipd_ioUG6Acqukt56kKv4YckLUBNYknJmrqWi5Lu6wNYLdYg-Dx-8jxt-Qb5zFygtRToEU9bVm8-cWw7ovtQhViA39K63cPFA","iv":"ig-gJGI7zCT9wv3b1MHf7g","tag":"7CT26rD6fntW-VlLGyC-K1G1HtKj2-2IbUtCDsbVeJI","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJjR1d6bVpoQURnSHFjby1fTVNnMGFxVFF1THVrZkpQTlJEMjlMVzYzc0FlV0Npa2x4eGkwZmJtdGVCNmIzbkZJIiwieSI6Ikcxd2xad2FxblN6UGdhQTR5N1NXYlJvSnA2X2RxcWVYY1RnYjFoLS1oLXBIcEU3T3JsTGxlNFNCdGhJT04zZjMifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}',
            ],[
                'input' => '{"ciphertext":"3UPzi-D2Y9XsicFloqdgj4cuq1jRvtlgCKXANc-Xdexu7DbPrY6IwzRQWWAEWjT66sizNMS5Y2B4Rc4EAV1jPl80yxVEopF5dZeNH7O68UluUqAPqSA6EWjM5f5EWarVVrterZyxE6xNZ816U5l51o75aGsO9WVTdHpLZYzPUQEJkU5qz3N25dCSJyplGWeQsUXMW_3D5Cy-rIdRqhN2F7BNxthJDNk","iv":"TjuvMx1Bq_KJ0xNB","tag":"C3D1dP9T4gHdAmhxES4Nyw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJHRDlfb3kybUhDRVlpWl90LVdWaVRLSUd6ZlR1RkhFVkY1R0w4Sk1YaXJya0poZzRWTW5VeTMxb3pVRVdjdklTIiwieSI6InNZb3JXVnBxWjg4LTlMMnUxOHYxSEZhM2QyNmRPX2QzektmYmZKeFhDUVNwOUhzR01GakhuZmctanRRdERtdXgifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}',
            ],[
                'input' => '{"ciphertext":"_mqiqICFuI7v0yW82LSth02MMKSDEZKo7w6ubVVkouvhBwjnNJ83tEWDBeGCi42QZia4gVe1ui4pEkOAFZGKCxEtD9-F1CXqFWtucMj5PrSQRttqdxie8Ax34B3AzLfldp_D1E1oOEMFc_d2-Bc0WLeucA9iOPAhUeihtJM_a5ifga81woh-vL6apREHfe6RYvi7qWxCWhdGW1QpKefzpzfgfTyimRs","iv":"rOK1OBP30EMMNNym","tag":"W9o3t8d0T-eN1_HJW5iEtw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJONHM1YWFIdVlfVWtLVU9FQkVJN2R0Wi1tS3lWalM2bXpvUjllcmtXUDg2U0JsUjV3NW1IejBPOUYxakswODF5IiwieSI6Ikp5UExRYUhvRkZyVk9BVldicXNDSkxzNHhYOXkyZFdPSzR4b1pNWVlRQVdROVBIUFgyT3lJN18wei1NS1dlSXUifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}',
            ],[
                'input' => '{"ciphertext":"yz5ZH9smDNoxUhB4WzhCGVlqZo8RkgGRssuXhCCJjPl3LZpeyG14uHkznZnviWcs7XPoxuCSwJf7iKbUvcv6DyGyWSvqNRQEpjsCCK4wYshZgSEo7IKSlCLNxlfGs_VcVuyqB8rr07VBn9Gmwzsdzo_-Z8rjTPUDcAmFqXokzhiKYHFczuOe1zQnPGMrw0hy612VSd6Gy-SbvaRxelbfsWt35vNP93Y","iv":"xdhe_UIQo8GRQL_s","tag":"3n91W0VMb2WGTsdzMmanLw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJoaTdhLTBhZzBRSXF2TFdmY3R2QUNqRUM1RjlXbjdBOUhjM0xnTkdzMG1OZHowaXlCdDFnWWIwMHpaTE9wX3JpIiwieSI6InVHclpjdzFvYWJDSklULVpBWFdSeGVicXY2ZXFXQnhlVHJnQVpoYjAtSHN6dWdsT3p0Y0dZSk91V2d1bDhGQWEifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}',
            ],[
                'input' => '{"ciphertext":"tUaUs-lWx436zt0Y3QCWduAr9t_F2toDRvmlBQ7JIiHGguXbzpKgXHFFc36u3zfUuZL5i4xuAuf3QNmW-TIiIQVorjcCwtrrtU3C9ZNK5TNMGF3bgCuDoPxfnOna-htzLnighhYHEPKCnDCBpakeNb8BtzDAm490X7yteNsXGP5mO2VcucfRAhV2bZ_qJQdi62SyWdAvh-3aU82pa8xQCR970AiwLAhY6qPxZszGpVg","iv":"7gdhaz0uIHKxde6LK4uyTQ","tag":"vyT9gPezFcG7Bl0HDbkB4A","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVW43cFpaeWlhY2JIRjl6OU0tYWl3eGR4cmo2cldSSkRDOW1iTTRqQ0tDWE1LLWhzb3loV0E1SG1QeW9URFkzM2puN2tuTXB4Sm02UVloa25PTFN3djRXIiwieSI6IkFaYXhiSmJKaE0xUUFVdUJmVjFZNy1NdHVJSFFjQmxrOF9MUWpobE9rSFB6NEJZY1lOazBVcWxCSDJ4Vm94VEpaMFJFcWgzbkdwdnBDd0VkVjQ3aXZZMXAifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ"}',
            ],[
                'input' => '{"ciphertext":"OFr80rFYP8DAa2Ww68cFNl_vEKL-2ZW5K-UY3cO3gFRuGda3SHWGm6izPf_e3zd_lKnyyT79rGQp6VIuBDAWvak1hgioWvxCy60eimve4vZB4uuYJB-xNRJHj_wFScB38zU5yPBMPicXfN5CvhAkIqjqSJ0TyyRBaom29elmYilrVdS069vCb5Wa7l8mecva8zQO9w0kXnbC-ANxEwehNXMisVEivas991jPuuiXByo","iv":"bQHB-I1nfVUE3tgpPfEfEg","tag":"87GQCsKcjs-q8RI-0U6V4up0LAixjTqM","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBYUdZWDZoOGFkc21ydGJzVEo0NjU4eWdtTmx3SDRoSFQ0RldCUUpOUEd2ZnVnUzBCYTJPXzdkMDhreEtibk1QS3MwX0pFU2NVZFYwcDFURVY4NkFCczJJIiwieSI6IkFKUnprNHFEY0hRMUJpVWNoV20yaGtWaldJeFNwbl8xUEUwRVI1QUR5aU5ReVJoSjlBX21haWFIcGFhekR1bTlNZ2FOam1CeEdpRGhtNmpZWWRzbDR3WkUifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJDQkMtSFMzODQifQ"}',
            ],[
                'input' => '{"ciphertext":"h5kyzFB1e5QCrnFTVD_dWBuuF29i9r9OZIdqg3NDU76tqLMU_pnFrU6lNeTR0IzRWCtIGQVmm2YwtuVYpxjMNkuqulKtYzNpL5xCD8HdghCfI5y65fcY8wR26gBTeKXeCM6kiOtWcUsjMiOW6hX9BbZvo_LnMl-KYDok_hxKl7R1_8GAs29NxIdHx6hM1A-9765OcMp1QbEH-EuSqVXTvyPGoECu0-oh6W3nFMjzoA8","iv":"b6IIfIycY1YarV2iWaDoaw","tag":"GKW6aJwXyTiEga_5LUSQE7Ek_NOGFdKmoxWfS5Zhvb4","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBVGRyUWZfalh2bjRhdUtHTW1lYlUwZzFxal9GUzg3YlZoZ3VMeVoxOUJ5UXVQTTVaMTNXOW53LUdxWHY4M0ExX3piRlBlclQtazBWT0RvSEtwRnRRVy01IiwieSI6IkFGeGo5WmJITTdNSDZyOVhIQWxsTUdFd1pSemFpbXVvWml4bTFYLWZSNENJTmoxdElobWhnTHVGUlFSQXlWcExOeDIyR05GQmU5UldpYXI3MjNoMldNMi0ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ"}',
            ],[
                'input' => '{"ciphertext":"8_r4milajq0IjF3TbyT606ULdk-S9PkoGn4HwPff8Chi5jp9QCo1huX6A-6sQ_1-R2SeWrMwzWYw-ibM14HXU7-ghWYTl_GEVTyWtGoSoLMRuZlgzMsJGr0NxvxeOdUK9QzlWdlSfvJ8L6RfaHD2mH85sI6iE9-YS5AI9pxFRwdxZH708_zCLvmMJ93-bzamLqNIcQT0MD337x1fYKjtvBCQQ2i3Bbk","iv":"vfVE6WKp_DhUGJtL","tag":"LKWP3sbkAr1xvWP-Pn8OpA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBTllVU3BoTExfbjJwZV93Sm1ZQXhKQnlvNGlBbWY0THB1MVpRRENTRGJxVmJ4MEk2V29DY3NRYXpzbnhLcWM5VUY0VEQtQnJxUmdkYUFEQ00zcWRQLXMtIiwieSI6IkFkR1d4NXhLUmJRc2NvdGNhbEJlaEhzVjZ5Snp4Wl95d19FUmxzYUZoaEdaR1VVU2U1ZjZfLVpvWWNVcE1SVEtLSlBMdmZGMmVSdUE1Y2Rfa3k4aTFNWVQifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExMjhHQ00ifQ"}',
            ],[
                'input' => '{"ciphertext":"6wwkwXYVoP6HV7z_xGPIxp9K3vhOMYtbXGSXCu5tQoWiloqsvu86WrwjORxOnmL7oHMaw3MvoIglJ05sD6dn-65nFPzqqCPqtf2ejevV4I_EUkNboisEzZGL9Zg5iujw5KustlIZ0ub456Xo3s9iGWTIUqxK2qY-ejKGLPArA470TDv1CEWGWgIhqoELc6W2TS_W3yPap0N-9wP7yQCVd9E5tyl_QP8","iv":"ik-unU3qVlJ7iS7J","tag":"OSzgRhcPbQSP6SHpvxP-Vg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBWm9kTmplZVptUEYwZlJYNC1vTWdnRmI3ZlY3WElTZTdrTTVQXzRRRk9BRWt2VVo3OFY0Zm1zX19uSjBQbml5VGFIMHVFaVpiNVJfOGlITGZjYjVTeGNJIiwieSI6IkFWQlhZeE15TmNtakl0OVB5TkxtaENZWGRDZWlyeVliTURBV0tCSWpVY2s3R1JDck4yTVM3Q0VwSWxMc2Q5RFRjV1ZCZS0yMzJfMHhnMjU3ZzRXNndXNG8ifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkExOTJHQ00ifQ"}',
            ],[
                'input' => '{"ciphertext":"f-Y17Op4tSEbhAdh6CQ2sWmn_kTecW-X4IWUT9oMaqzBC_C1BA319z5NM0yln9xZTkXDTUI4V46CiXAz24fkq6bUD_UB89qoJ_liOhvv7uDm__RqEYq-1M4Y2iAtmsoS3itdYt-VVCqj0No5o_Uy846pzwIWOv5W5lGFfsllwuXcUtCGAc7NiuGEG3rGhKylgCYQXDF4XZp-Sil-3tIlzplz2oU_Wb4","iv":"DyIY61bEPjcvKN_g","tag":"XHQb3RJ1R4XDE9Ww-LHGsw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBUHhfVXJPMnp3WnVEVGtvdTRUeThKZlJsQ2NFUmRrNVVVUjczbXpZVm1ZQlZVNy0xd0JEWldCdkFJZE5WbW5HV0pqdnA4cnNIWDZuT1RHNFFPWEd2V2lHIiwieSI6IkFFajNLS3J6U0FSWFNWbUFkR3U3cTQ2cWI2ZFctWlFYQWNaZmhfajJESnJjZGJFTlRiOE51MzFScGJ5X2p0SGxuekp0cjRfalJ4R3RGdG4taHVpR2twdzMifSwiYWxnIjoiRUNESC1FUyIsImVuYyI6IkEyNTZHQ00ifQ"}',
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
