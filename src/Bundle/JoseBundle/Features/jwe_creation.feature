Feature: This bundle provides a service able to create JWE

  Scenario: I can create a JWE in JSON Compact Serialization Mode
    Given I have the following values in the JWE shared protected header
    """
    {
        "alg":"A256GCMKW",
        "enc":"A256GCM"
    }
    """
    And I have the following payload
    """
    Hello World!
    """
    When I try to create a JWE in JSON Compact Serialization Mode with recipient key "jose.key.key0" and I store the result in the variable "jwe_compact"
    Then the variable "jwe_compact" should be a string
    And I print the variable "jwe_compact"
    And I unset the variable "jwe_compact"

  Scenario: I can create a JWE in JSON Flattened Serialization Mode
    Given I have the following values in the JWE shared protected header
    """
    {
        "alg":"A256GCMKW",
        "enc":"A256GCM"
    }
    """
    And I have the following values in the JWE shared header
    """
    {
        "foo":"bar"
    }
    """
    And I have the following values in the recipient header
    """
    {
        "A":"B"
    }
    """
    And I have the following value as AAD
    """
    A,B,C
    """
    And I have the following payload
    """
    Hello World!
    """
    When I try to create a JWE in JSON Flattened Serialization Mode with recipient key "jose.key.key0" and I store the result in the variable "jwe_flattened"
    Then the variable "jwe_flattened" should be a string
    And I print the variable "jwe_flattened"
    And I unset the variable "jwe_flattened"
