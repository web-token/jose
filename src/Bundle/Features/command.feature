Feature: A Console Command to rotate keys

  Scenario:  I want to delete a key
    When I run command "spomky-labs:jose:delete" with parameters
    """
    {
        "service": "jose.key.key10"
    }
    """
    Then The command exit code should be 0
    And I should see
    """
    Done.

    """

  Scenario:  I want to delete a key set
    When I run command "spomky-labs:jose:delete" with parameters
    """
    {
        "service": "jose.key_set.auto_signature"
    }
    """
    Then The command exit code should be 0
    And I should see
    """
    Done.

    """

  Scenario:  I want to delete a service that does not exist
    When I run command "spomky-labs:jose:delete" with parameters
    """
    {
        "service": "not.a.service"
    }
    """
    Then The command exit code should be 1
    And I should see
    """
    The service "not.a.service" does not exist.

    """

  Scenario:  I want to delete a service that is not a rotatable service
    When I run command "spomky-labs:jose:delete" with parameters
    """
    {
        "service": "jose.key_set.jwkset2"
    }
    """
    Then The command exit code should be 2
    And I should see
    """
    The service "jose.key_set.jwkset2" is not a storable object.

    """

  Scenario:  I want to regen a key
    When I run command "spomky-labs:jose:regen" with parameters
    """
    {
        "service": "jose.key.key10"
    }
    """
    Then The command exit code should be 0
    And I should see
    """
    Done.

    """

  Scenario:  I want to regen a key set
    When I run command "spomky-labs:jose:regen" with parameters
    """
    {
        "service": "jose.key_set.auto_signature"
    }
    """
    Then The command exit code should be 0
    And I should see
    """
    Done.

    """

  Scenario:  I want to regen a service that does not exist
    When I run command "spomky-labs:jose:regen" with parameters
    """
    {
        "service": "not.a.service"
    }
    """
    Then The command exit code should be 1
    And I should see
    """
    The service "not.a.service" does not exist.

    """

  Scenario:  I want to regen a service that is not a rotatable service
    When I run command "spomky-labs:jose:regen" with parameters
    """
    {
        "service": "jose.key_set.jwkset2"
    }
    """
    Then The command exit code should be 2
    And I should see
    """
    The service "jose.key_set.jwkset2" is not a storable object.

    """

  Scenario:  I want to rotate a service that does not exist
    When I run command "spomky-labs:jose:rotate" with parameters
    """
    {
        "service": "not.a.service"
    }
    """
    Then The command exit code should be 1
    And I should see
    """
    The service "not.a.service" does not exist.

    """

  Scenario:  I want to rotate a key set
    When I run command "spomky-labs:jose:rotate" with parameters
    """
    {
        "service": "jose.key_set.auto_signature",
        "ttl": 3600
    }
    """
    Then The command exit code should be 0
    And I should see
    """
    The key set "jose.key_set.auto_signature" has not expired.

    """

  Scenario:  I want to rotate a key set
    When I run command "spomky-labs:jose:rotate" with parameters
    """
    {
        "service": "jose.key_set.auto_signature",
        "ttl": 0
    }
    """
    Then The command exit code should be 0
    And I should see
    """
    Done.

    """

  Scenario:  I want to rotate a service that is  ot a key set
    When I run command "spomky-labs:jose:rotate" with parameters
    """
    {
        "service": "jose.key.key10",
        "ttl": 0
    }
    """
    Then The command exit code should be 2
    And I should see
    """
    The service "jose.key.key10" is not a key set.

    """

  Scenario:  I want to rotate a service that is  ot a rotatable key set
    When I run command "spomky-labs:jose:rotate" with parameters
    """
    {
        "service": "jose.key_set.jwkset2",
        "ttl": 0
    }
    """
    Then The command exit code should be 3
    And I should see
    """
    The service "jose.key_set.jwkset2" is not a rotatable key set.

    """
