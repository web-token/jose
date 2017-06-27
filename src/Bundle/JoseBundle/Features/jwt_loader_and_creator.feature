Feature: This bundle provides JWT Loader and JWT Creator
  These services can sign (and encrypt if needed) any JWT.
  They can also load them

  Scenario: I create a JWT and I load it
    Given I have the following values in the signature protected header
    """
    {
        "alg":"HS512"
    }
    """
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
    And I have a valid JWE created by "jose.jwt_creator.main", signed using "jose.key.key0" and encrypted using "jose.key.key0" stored in the variable "jwt"
    When I want to load and verify the value in the variable "jwt" using the JWT Loader "jose.jwt_loader.main" and the decryption keyset "jose.key_set.jwkset2" and I store the result in the variable "result"
    Then the variable "result" should contain a JWS
