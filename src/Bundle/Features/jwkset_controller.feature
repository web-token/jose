Feature: Shared JWKSet are available through a route

  Scenario: Route names for JSON and PEM keys are available
    Then the route "jwkset_all_in_one_public" exists

  Scenario: A client wants to get the shared public key set (JWKSet format)
    Given I am on "https://www.example.test/keys/public_keys"
    Then the response status code should be 200
    And the response content-type should be "application/jwk-set+json; charset=UTF-8"
    And the response should contain a key set in JWKSet format

  Scenario: A client wants to get the shared public key set (JWKSet format)
    Given I am on "https://www.example.test/keys/public_keys.json"
    Then the response status code should be 200
    And the response content-type should be "application/jwk-set+json; charset=UTF-8"
    And the response should contain a key set in JWKSet format

  Scenario: A client wants to get the shared public key set (PEM format)
    Given I am on "https://www.example.test/keys/public_keys.pem"
    Then the response status code should be 200
    And the response content-type should be "application/json; charset=UTF-8"
    And the response should contain a key set in PEM format
