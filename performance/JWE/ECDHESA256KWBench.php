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
 * @Groups({"JWE", "ECDHESA256KW"})
 */
final class ECDHESA256KWBench extends EncryptionBench
{
    /**
     * @return array
     */
    public function dataHeadersAndAlgorithms(): array
    {
        return [
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A128CBC-HS256'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A192CBC-HS384'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A256CBC-HS512'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A128GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A192GCM'],
                    'shared_headers' => [],
                    'recipient_headers' => [],
            ],
            [
                    'shared_protected_headers' => ['alg' => 'ECDH-ES+A256KW', 'enc' => 'A256GCM'],
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
                'input' => '{"ciphertext":"elqZ_VKgwp3sF0hD2DPADwaNxB7oeRl3l-G-WIQ9Rcisfasr0d0EoFo3I2NA8nrwiMLI40cD4wFRoMmhcp2pI_bx0kwX-sw60UL-smvKyvFRTDA6XrObMfL1r3MCrkBFhVqvuUo_TxRHqETIO-aUFtrJnw318YjCF6DQJEYyds7CV5eH3tnURFBX6eJRCHTl1LmfiFhwd-TMyuOghkOaw9qQjoU_WsTlhazni_i9qjc","iv":"tY_Uoe2fj0yAnh9FS1K9Hw","tag":"sXA3GYsr2aJy1ut7sX6vTQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJEaW8zMjRLWFA3SnFuazZHYm9ERmNVNlgzSUM2eno2ZU5JZTczaWZKTDBzIiwieSI6ImdMenhkUkNPQjdpVFhiTlN5eTNDWFM0bVBsRnBSd1NBeGJ5Tkp5YUpRS1UifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"JkAEt6tAJ6D8vtmIVGEd1GXWkJHIekyfHUPZCWBLrduafpaSkjw28w"}',
            ],[
                'input' => '{"ciphertext":"OAe97MVk-JwZ7BrNzf-U-nRckM2GVbFfYJ7DSHu9qdter6WVZP83dKvuVdZzhLg_KIw0cESvma9I3Fja5lx4YyqAopcflpV9EKiWH1l-sPoMpuaXHDILFH0KLPrR9MOvMD0lMaqdbqWjJmu-qrj8b8FMpt4SFhoOoC3--85x-JzGuvVN6Gh51X0oGDJIQgLm1yQQ7roOMlRWqS97KFRqLAGBoCLCLgmjdsAnIJbijlI","iv":"8FotWhpZ2wLPGdotJ5KlWg","tag":"ovtGJLB1Pefd45Mwd4v_nMvTmF7J_FW-","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJsWjZtVjlBR1lDeXVILXZUeGhHbmJ0SmlKVm56V0VjbFdxMG14X0YyOUlzIiwieSI6Ikg0Q1FhZ0JSM0YxNHB4ZGoxUjd1M2VvMExRbUdyajM2c0Q0TzBzMlN2QVUifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"n7FcIsDQ0NdwFpFkBF_ECvhJHwPnkx53OUIoe6fQmr3wpLuCxChwkILdwqAaBT-ybTwuVAbrx1c"}',
            ],[
                'input' => '{"ciphertext":"n4bkTRBpvjIRW0fZRbKCj3AyQvAozK4-jLjMTDQ7kzL2y720Q3kEmSNz4SGsaTQUBu_bC1uLNA1ZouR1ntSbQcPahu35OgJdLwqLuMwB284ic7JI1qM_7TNzQmeUlVhryIFltSI3UKhaglpDX7snUNMOg88CbwjZEb9h_J26rdaX_vxZYPmLKq638CFpBZIXBE6KvoMU1ipQPimnd5OtOYyU5EwmmJ5Y2ttxBVtN3zE","iv":"UI1njhvV_8GxEnnBcpMdmg","tag":"-py-4_Pg_n9du_2BOSngrhemIwiggD4I1pWNFssBATE","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJ6LTloRTN0QWkzSC05cjJGQV9ST0ItcFdJdGJsUDNjbjcyT284aXhxdlBzIiwieSI6IjJwdmtTMlpuNUM3OGFEdmR6aHY5N1UzcUFXdnVEa0xja2J2QjMwTllTVUkifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"Om5KrcwO7-QwDdkyM8NaQwbnbN1kYPVHcujhv2CuLU0_rcCEb7zo7aoHpdVpiGwwiptKmXZek_XAX6iJxAVY3129sIkJkBiD"}',
            ],[
                'input' => '{"ciphertext":"xCjlpYOg0MkgG6Ysgg76HXkFL8_anKWo8jLdlQbZHb4R_WP1cmsjHXd_XP5aoLnKmLSX5UPLGIcDwqx7i4AKzmal2XAST_0z3pGfeoAi6oy22bI7H_Fp1NXAti4KQrhHIW6WbKFBulmfqJ_xg8zc3B5kT6-0D4-TrOnd9pms96Y4Q2GhgNmbHBrh0fOGt0WzSgFvs9DRDTPnk9x_hiF5btOw6vfxyUY","iv":"8KaltSMM0bg75ZlG","tag":"rW2rE4QhkW7GdqvP1AozoQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiJvME1wLUtack16XzBXR1RCZmtaa2YzZ2UweUJFRGpiR1FyRDFObWg1Y0tVIiwieSI6Ik5wWnFvcGJRT0JBb0d0dEE2SVRIRlFCempyVWc0M0IzWHJmdEloSlotRVkifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"xlLHgBJ1wUnXxDO-XFN8uvzm1vaxYzeW"}',
            ],[
                'input' => '{"ciphertext":"rle0Pmd3TT0nc-KyGW09khRgM2V2-6e6GZxVvGUQrs8eJWhvEYCnnuXQbXBloJq0FJdRV6xDV0G-4Yz6OuARivm3CSmIDUTMEDzRJtWLq_5yJCFI1dpeNTTMAqHJkJQ6jkBhAAb-VdQ4C0G2kUvU4-F_PVWr90mMqZvvb45cUGQvqqG9n9KamJdnmuPORnzvwG6UEVLiTc0DMlZ3CQzh_q1xczNYI9c","iv":"sn3zgsbk5Be8n11M","tag":"Lva0WP2lo9EA-J7S9O1fKg","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI3NEtzRGhnd1RUTlRlSi1IRjNjQ2NQOGtPaTJDQVV5WEMwZXBrcE1yNEVjIiwieSI6InZpNWJsZ2x5RzRrM2ZucVNKb29yUUxwSEgtNzFCWER5X0p4MmRJbGFmc1kifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"7e20bz6RqpUrLy3-eCOrTO2ptEsXv3DPgVpG-zTvBXs"}',
            ],[
                'input' => '{"ciphertext":"8jfsjBShHGOeKpHWv0U9krkP3JVj8n66Kk_jQkvwldPxmUNhR0PYyOSkVFh7w4A-WnGq34knO_E7CF72fyHzhqAkysouIrS8t5BiqoD0Gy193HpxsuA0gOCFxvJZy7sgp90NugVcpPbODqM1iom2NAqTA3tIdGBwzDYcD3cYW-OUg3_rC6f4DcM5iof9DF4R0c6UUJrlIoSvqUMXcaiHDwhw84ZurIM","iv":"uIJyDwnWoQM6JrSG","tag":"ynA8saYAPoJrP5CoqDq-qQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiIwZXUzWEpkMExTQlh0UWw0R0twdWc2VWNyMTl5Z1B0MFFOYXBFbWoyOWFnIiwieSI6IlhQZVo0aUJrS2J1SXRCb2lEcnJqaEppTjFTamhvWFpTLXJLdnI3M0g4cW8ifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"VFMoCahb0HnBT5R_PXhnWGWUUJLkSz5V0Xa1OnQwMex0h85DVKptCg"}',
            ],[
                'input' => '{"ciphertext":"rFHkQLgkZaoTBg-oLFEO4o1LZeKDl9tVWdO742ZetGDtB-_AczIXbT26un67-mJb55YqM7HDQfoBJJlutS5gdNFF93btQb5yeF5MtVQxn4lx6RkWdTZZEV1hM7LyX_6RLd583BRSkTDlePs78jTCsZOWXcMqf7qzUlVRlxzk4aMAjTgtAXj7Yqonwn2VPYL0Nyw4NZKLd9rPwXv9C7th9tuLE-il_XTmPaKMhbMUXvA","iv":"hvvs1yliOVbKhpFIOc45mg","tag":"OyzQP-VHL9i9Vr5Bi-gW6w","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJQdGdmU3Y2NlhBOVBSalY3ZlJ1M0pJNzZZcHVZYlBfb3l1X0RyaENLS3VPTGVlS0lSdnFUMmJscGZHWGVnR0wzIiwieSI6IkUwWGM1M0s1TGxfc2dEak1vZ2VoMGd4NTVRMjBEY2xBdnB5M2Qza1dtQm9lelpwZlRCSmVZMmJ3cXVxcWxTSnoifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"NGy6mQZolPMY_WhO_u4Fl3ddCi3NhY3aK1k-pUCHn90mlpuWHrWLIg"}',
            ],[
                'input' => '{"ciphertext":"F-YJHN075Y44z5p0u42QphlNTKfqWF3WDRSxTZAGtvfwI0avIKuZDPyWG-GGS9KlX5Lj2ITppY7sezA1KrXo7Enlv8DxUTHcHwnbNX-7FtqOI9ETzFFT-GyVxcS-aGJHF_yDB-VVmJmc6PKUB6YJFwwgo2kyDSHg2JwC8Nadns67OkD8FxOwRdsmImB_fngGySrJdFT9RIjw2Qrf_B2jse8DxZxAG5-HfpzmtY6RN3A","iv":"CmST77PWGlDeK3eExarM8w","tag":"mN9aAW8_RoLMevVswbbDc4BVoljGwtYy","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJFQm9UX1hORC1qd2Z4M3gyd0x6NDVkVFViZm1OTHhFQUlLVENNNG5Wekt4TTVtVlRYd2pxamUtVnIxTDg5M1lyIiwieSI6Ik9YOU1fSDFLenhCcWs5QXNZOFQtWThkUExrb2V6M1Awcm9SQkVxZlItb2lCeXlaVWp1Y0ZaRENkZ2VLbnRhamcifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"7rXxo0Sx8bY-AjJ4rSh4Z1g1YF9ZClh78DUBIX3AYxicC1r4HVS29PVon3pjCI7coEtE5-a7DSQ"}',
            ],[
                'input' => '{"ciphertext":"E7zogW8cH5U9Zn0bm6H6RnZ79RX21Su0yd3Fdg7bxS3LiCLOThrdQVAK8UlloNrHoVRAzRKmWW-3qZlzqURbO1eXFlSB6PPAhfH8yhNgPL_OIYNdXgrVuN4RcnWi5TrAEDx4ExXSmRfS3rm8KASjvqGlPQrhAWYbmp2bo5_SCLl-sQGSohArHUb6sgOX_VBz_1tDvwVlK5KEf-MrK48j2gEkP5-tHO8LOOaeExB256o","iv":"jeq1MXS63KY6rh5iXc4I4g","tag":"6SIbqSEcf3brat-pCV1cYQisr9tft0S9tfaPDYS4YPI","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJVQ0psd0ZpTFZRSU5fOE93d3JoT2ZHMS10dGNia1Zzc2J5TWZDa2xiNDM3NldPTUNKVFFlazZGVkNpb0xDYUR5IiwieSI6ImYtYkNrTHA0LUZkNVBUZHptT0VQTjhKOU9uMkRYcEpkdG1LVFRzeUNDSHNQTUpTYm91dmliWUJrR0F4SXZjakoifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"aKjxkCBdoGJFGsMyC0k4NdsEhyAe5p05UyggplMHonxotRkVsqTJxw-pWCbX2d71agLSuOK_8mzSW8G3Mcgw4jdzjPHQmnY-"}',
            ],[
                'input' => '{"ciphertext":"rng6IeMHQtIw-TFu-t5ymBK20hEkWrTZqQxGHF52CN5zcuB8TDYTBit4-1Tn3JLPbdk7MCNX_DFj0zJRpIoXFkI4axqHCtZxllhHOeK43nIa3s--QkDImRquUaNSTPxGUWQ0MB5rsuIdBiM2YvcBNS29iXxNwdOI5ThA1Ecr5-tMqRxjDCWqyMK34Bf8qy9l7xOczxGEf_WOC8nvP9GAMcWFVvtRSe0","iv":"aKetE6StHb7VbKAk","tag":"4u007kW8uIuVeMXshIYY3Q","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJOUl8zYkZEQzBJQU9VcmtzVXo4MlRJN1lIUkNvMmxCUVhIQkVDRk1mcWF5Szc3ZEczOUwyejRlbzMwUnItN3VJIiwieSI6IjZsMWxrQmxabHlibDZDa25ENEFGZ0F3Y2YydGcwX05Oa2JEbXhtSjFLVVdCZ05vUEZZM3FxV0MzOXVtVGJtRWcifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"OXCbzez8hAMguSYL8Og0MrQEM4kfr_KL"}',
            ],[
                'input' => '{"ciphertext":"wIxJtoXQ9HCH3pyw3UkvdnS3-lNiksWlEE12eUIoxNM9lhImsdQUX0WA0Jm7YD2Vv3W5TnTamDmS6eabGPmS_nzeaRi0JxLaMYqiHtWZDNUmXNSb1iSz7hXbBXhK3QdoJLW7cBSvzkuQtYM5Q9WXA5VT-jDsYycfHmjFUS-uDmhx6l5doi0Bnp6s8DWLQmqZpwn0id5jL-LlkUiS2ujMq_ON2_wsY-0","iv":"35phum4i5lJTQOSe","tag":"6FB-HwfFRC5VKb40Y08VSw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJnRXF5OFlPS0RieWtHTUFremQyNDBLM1NGR2lsaDlPRHg5WGxPZkxiUmY5X3NhZ3I3Z2lmR2M4ZjhJcEVGOUJhIiwieSI6IjFTX0ZTYWZqeG0xOGkxSGZMY2dCSGpQZFJKT056RkJqUld5aFo2U0NkQ2pndzJMdkZOa21XUTQ5MzktTHBqMU0ifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"__0ppLCyQAnZef0VfoCrPKjsq5_8mV75kM0dOwkPPP4"}',
            ],[
                'input' => '{"ciphertext":"Abqf-vf50aUzT4zAljAqxgo5UCNYasYNdoMTmRfc2gFvbxScRrbHa3ovsyMyjD0RV-5wO4tD_Z_52nJ-KHWW5Ui4CLoC9P_81b4GmwfmWXxVX8aXObc55qSZcrCOdRUANBC8WqYq2ugFnUCQ6PschBh4wswfHBuffisnfz1j2Z9HKerAvhtnqRs6Uq_XsXhOb5913NgaajhQz0avdok47b3CkkYIAeU","iv":"lZhDjhnLnLdMfY8O","tag":"IKNPwmPYMRw0vjBTYatDrQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJTN3J2NzltdjIwUnQydWlfZmxmNDhsVHA5V0tVVEtqbHJaTGFJZjZzZHRybWp3dDhPMFNyY05FLVpoQXhWdDRCIiwieSI6InhWRGUtc0pIcVpCdEtqVG9UUk0xOGR4UzJORi03Y0FSMlN1SlhuSE1qUjhCZ3V5NW9yanRoN0RicFZGYlpJdGkifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"om9jhvtogndVbg_LQyx18VEqrXaDGvLpXnz_ERsuqI036ERK4g2Dww"}',
            ],[
                'input' => '{"ciphertext":"4j7GKoE9Gar5d6PhYuctNMKu-Y6637dqwoBHc56RUf4BETAls8UJxZeGmGKIbe2gwhtJfOIecQTapWk8NF6efaEzudYYlB3Dov9vxdGS9EVN4HrjcVlZFTNKZHCUkPgSpxXJRhmFz0a4pVgBUDyDQQhxLSUrkcIggoQW5Yz5NFgsbozQUpfKwJIkfJW_4aEzccYsq21zPcIBGiCxB8Z3cRF9Cjk_kMJTItiupKYCDd8","iv":"e2_ze_AGW5bMS5yTW2kmiA","tag":"yR3pZjTaM0FCAhjoTO1fiQ","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBR2pZQkhsM2t0M3M2ZGFCcnZQTlQtNTFCM2ViSEh5OUhHeVdYQUJLQTdJbzVOdGpYcFFwbVhfanAtRFNJRWEyV2hyZVU5bEpsWGd6SXJvTTdDTGRYYnN5IiwieSI6IkFIZjdQOGdVc1JPQTlZS1B6MWh4dEFvN0ljemU2eHY2Sk41QTBnQk1XWEVFYjF6aU1ETlZKeFQ3VFVBNGNCZHpCODJDaXpyYkRzZVZBSjh5OFBlVDRDQ0UifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","encrypted_key":"11-21hxPujNIRLDr_8zEtRoB6rQNr4BNAViatSejPojnS-niFtp2bQ"}',
            ],[
                'input' => '{"ciphertext":"JzcgliLb9HDttswidS8jRAixP6IPOJDOCNBmHWjBsWoR1TqYdhV7W-ajOZXZXnwlHBIdt0s3HKWQg5nuIzdAG1tLFkeg0l02FA6Y4qUF_EGrwwr6FsiyG8Iw70yObyGafwLEi-ahhDTwAnaUoTxly-qOuYcl5WyEwwN0ZTSL_8Ev2A8iwujCq4q62IU7vMmcZ2kUVK8BtyYHRbmIWimXy81bt52oThNAhgfIgVYFQBU","iv":"8B7c5e76TGPVk1eu1psmwA","tag":"mZV3MMxoFcLcmf3lXC9cvc2eCcROMpoN","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBRVdWb3NOMFZqeE5kNzhWOGpyam5GWndDWFpZdGNKNTBMcFpvdHFVTEE2bEpCb24ySGZWT1pINGVvZVNQTnA2bG9penFDcVpLYko1Uk5hTUFqeUY5SGpEIiwieSI6IkFiT0FXTmJLcFViQUh4emh2YmdETTIzNE1zdm93RVVsWmNmTmxpMWtXTEs3R3k4ZVFROHpteVFlN3hYcVd1cERFN3ZhUTZmcENDTlV3cHgtdE9PdFctUV8ifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0","encrypted_key":"hoQ5T-1gM9Nh2wYcTCi2m80aIn-EZjUfaRwY06zUdGY6JVUnx-iEF1Z7Qf_C0C12nRtX1DmjD6s"}',
            ],[
                'input' => '{"ciphertext":"C00xUD6eGgYe6n5KeyxbWJA_5YXxtP76gtJhwC7Iz_wR79kAkbzgcrFHQjgEqc1fEKdL0f-oN-TX0qmv5O1qrhVuUI9Ci0ryyVN0dAMQ2DJYhfglRqbIrRH6h3jsN-8oTcEru8y9CBQGGEJQ240Y_15IPSTRAXddYhEBmd2f72WRC7j7a5qU0VR9uS0EOQIT0UEmoThb-hw-p6ELDtNF0NO8TLg47LCkvmrszvHnjlo","iv":"ATO6SkQ2xcne8HlB6-G2kg","tag":"TdFAxnS9chdQP0ZZ4HuDL6EDysisGU2yyEGIEC5BOg4","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBRk9rbGMzVmhMTTlmSUUwdzl6eUhDNHhRM1NOSmZZY0VYVG1xOGdRNGNsVXM4dzFiMG9TbFVqa1VKdmFUNlJJZ2NxOFhERG5yWnNGcGxhX0RFaTEtbmxmIiwieSI6IkFRVnhBUVR2YUxRalB2V013MkYyVnBzWmg1QmlYT2ZfSnE5T29keG9FUlZ6SFk1aVRMWTFuMFljV2JhalVIaVlkekNRaklYb0JZMTN5Qy1HQmhqZXpfUUIifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0","encrypted_key":"yf9a1TISudhHdyLnkKyqm1YqG40zIsiMa0RQVaRRlGbuLVu_BkDC2CMhYZPKDYjXRPzNktLL0XtNcoSF-toQiNxXka4d9j-l"}',
            ],[
                'input' => '{"ciphertext":"f6YT-Gm0hHbx1XQ8jb0gwkZLBW9-NuixMl4G7vCTzFVWamZZsbpnJ7jdqcPDh6C0gD-WmlLUcqVQ9CoF2BK1DADyrT6RzbCrE0IsiZLvcFidrCnYuoIVp-Sp62OaBsuhTPz8UZ6pRlMqeNaMeYPax0Wi_zq-ujBt1p-qmnI9v8LbfKRx4qYzqpPjL5VulxrD5za-6iRwMgu5-7kB22CCSl1adhnOaLs","iv":"Afklimh0N0bxxNg7","tag":"Zrunaca0toMAx9DtJOJiKA","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBUG12cWlvaXEyUlN3OTA5Ni1OLU82WEtFX2V1VUxmbWNieUowQlNhMkRkVWE2MEE1eEJXY0NVOEYxOUhRMkVrUF9oSWxTYjRrWVBjU1UyQkw4NVpkM2V0IiwieSI6IkFUZnpQUEkyalY3cENKX1ZQTXp1U3ZmSEY3eXItYU9MN3FLdTBtbVRNd3k4X0lheGx3R2VzN2J4eXFnUFdnVmNLd1hQR2ctZDRJQjFGTkNsWDJCa2lZejcifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTI4R0NNIn0","encrypted_key":"NqSzTnofID4klJJTj0P_1DWW3gEcNh_l"}',
            ],[
                'input' => '{"ciphertext":"lQU1sV5YVQ9JaqNem2TbwAOWYAL4SP4EQCPboUWkZzjzph32o5-Fi3hBtit65gc21GtBgM1n1arSLcwJ2EF3X6Stb8aYJjHjO05ZmLIVHS5RTfE7e7P56VoXmeH-JrgH4K5GQf0HEDr5xXr5PEDomO_JhfGm8CeEum8gaz9GlNi4Afc8k3s5qniAkvBOg6GfMEPaKs3awxNoJ8SLPGmDmJM9TCdpTsI","iv":"ty2brgOlAAlhEpWl","tag":"fRvH05nxpqHIW4Ujn5sRrw","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBSVdraXNHbWJweVhBZDdFdUZEbXpCUHg2M1p2Z3pmN1YzbmJ1SmZtOVZMQjNURkpRSUgzX1YxeG1iZ3ZwTzBQNHVNS040My0taXRtdkJYUVU3cGdxVnlNIiwieSI6IkFGV01VNnM4RmNhTGo4a0RwWHhCT2ZYWmJZUXlWa2RET0ZwRm9fazY4R0FHRUdMeHhRMUxGZkhqMENoaDBBamJZLU8ya2hsZ3VFd0FrLVZLdFgtc0pSczMifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMTkyR0NNIn0","encrypted_key":"WNplhnNqE_srETXR16MbQxFG27-0y0_sPj7CLiu9duY"}',
            ],[
                'input' => '{"ciphertext":"nqEo9zQU1dFRDReL2h9DNgkDZFB6k3hMWOBHaYswQTeMxyLefT9ZQPYZREMnWqvTL0BgfyubMCJMPyJqA9v90Vh3YWlWYlx2KjoacilaHpKu5u5z_O3_QMF9uZDwZtDWtxIJpYRcSGm07ecj-EG3iBLgGKIeDzVlQvj773iUqOBH1W6c1dozkTYk0GsHDvrIlYhnBmnmcfw_H8GJ43LdYtunfQon08A","iv":"7AQnFvSQIe27cz19","tag":"mvPeFciNbVXkIRg1Z0qC3Q","aad":"QSxCLEMsRA","protected":"eyJlcGsiOnsiY3J2IjoiUC01MjEiLCJrdHkiOiJFQyIsIngiOiJBSnEydkRaUXh2SDhfUHBXQUpVN0QwOXNGTHBIV25hUVIzZnhYeE91X1R4R0c1dnBJSHF5d3dMUnVFQ3dxa2xzM0piR2tRZDVaZmx2OElENW9QMmF5ZnRaIiwieSI6IkFYd2IxclNDTVFkTG9vWFIwUXpXcFlUdnZNaGlJLVByaWJTS201T19EYS1qdzBEbVVVVmJheW5oa3U3eHlvSEZibWdtMDlPc0ZyQTl1WnRZLVBhUUc1TDUifSwiYWxnIjoiRUNESC1FUytBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0","encrypted_key":"D2sKfMSjcKvEb_co6Gn_at8XHewMpBosZ5FWb6lotU2PYzqU_C4nWQ"}',
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
