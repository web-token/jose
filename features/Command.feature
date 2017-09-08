Feature: The user can run commands

    Scenario:  A key can be checked
        When I run command "key:analyze" with parameters
    """
    {
        "jwk": "{\"kty\":\"oct\",\"k\":\"dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g\"}"
    }
    """
        Then The command exit code should be 0
        And I should see
    """
    The parameter "alg" should be added.
    The parameter "use" should be added.
    The parameter "kid" should be added.

    """

    Scenario:  A key as a service can be checked
        When I run command "key:analyze" with parameters
    """
    {
        "jwk": "jose.key.key1"
    }
    """
        Then The command exit code should be 0
        And I should see
    """
    The parameter "alg" should be added.
    The parameter "use" should be added.
    The parameter "kid" should be added.

    """

    Scenario:  A key set can be checked
        When I run command "keyset:analyze" with parameters
    """
    {
        "jwkset": "{\"keys\":[{\"kty\":\"oct\",\"k\":\"dzI6nbW4OcNF-AtfxGAmuyz7IpHRudBI0WgGjZWgaRJt6prBn3DARXgUR8NVwKhfL43QBIU2Un3AvCGCHRgY4TbEqhOi8-i98xxmCggNjde4oaW6wkJ2NgM3Ss9SOX9zS3lcVzdCMdum-RwVJ301kbin4UtGztuzJBeg5oVN00MGxjC2xWwyI0tgXVs-zJs5WlafCuGfX1HrVkIf5bvpE0MQCSjdJpSeVao6-RSTYDajZf7T88a2eVjeW31mMAg-jzAWfUrii61T_bYPJFOXW8kkRWoa1InLRdG6bKB9wQs9-VdXZP60Q4Yuj_WZ-lO7qV9AEFrUkkjpaDgZT86w2g\"},{\"kty\":\"oct\",\"k\":\"bwIAv5Nn-fo8p4LCEvM4IR9eLXgzJRs8jXCLb3xR0tDJGiZ46KheO4ip6htFKyN2aqJqlNi9-7hB6I1aLLy1IRT9-vcBoCSGu977cNAUuRLkRp7vo8s6MsxhB8WvQBDRZghV7jIYaune-3vbE7iDU2AESr8BUtorckLoO9uW__fIabaa3hJMMQIHCzYQbJKZvlCRCKWMk2H_zuS4JeDFTvyZH1skJYF_TET1DrCZHMPicw-Yk3_m2P-ilC-yidPPoVzeU8Jj3tQ6gtX3975qiQW7pt2qbgjKAuq2wsz_9hxLBtMB5rQPafFoxop7O4BklvZ9-ECcK6dfI2CAx9_tjQ\"}]}"
    }
    """
        Then The command exit code should be 0
        And I should see
    """
    Analysing key with index/kid "0"
        The parameter "alg" should be added.
        The parameter "use" should be added.
        The parameter "kid" should be added.
    Analysing key with index/kid "1"
        The parameter "alg" should be added.
        The parameter "use" should be added.
        The parameter "kid" should be added.

    """

    Scenario:  A key set as a service can be checked
        When I run command "keyset:analyze" with parameters
    """
    {
        "jwkset": "jose.key_set.keyset1"
    }
    """
        Then The command exit code should be 0
        And I should see
    """
    Analysing key with index/kid "0"
        The parameter "alg" should be added.
        The parameter "use" should be added.
        The parameter "kid" should be added.
    Analysing key with index/kid "1"
        The parameter "alg" should be added.
        The parameter "use" should be added.
        The parameter "kid" should be added.

    """
