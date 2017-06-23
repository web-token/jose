Feature: This bundle is able to use keys and key sets
  These keys are available through services
  Key sets include keys and are available through services too

  Scenario: A Key is available through a service
    When the service "jose.key.key1" should be an object that implements "\Jose\Component\Core\JWK"

  Scenario: A Key is available through a service
    When the service "jose.key.key6" should be an object that implements "\Jose\Component\Core\JWK"

  Scenario: A Key is available through a service
    When the service "jose.key.key10" should be an object that implements "\Jose\Object\StorableInterface"
    When the service "jose.key.key10" should be an object that implements "\Jose\Component\Core\JWK"

  Scenario: A Key from a Key Set can be used as a service
    When the service "jose.key.from_keyset" should be an object that implements "\Jose\Component\Core\JWK"

  Scenario: A Key Set is available through a service
    When the service "jose.key_set.jwkset1" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.jwkset1" contains 2 keys

  Scenario: A Key Set is available through a service and loaded from an URL
    When the service "jose.key_set.jwkset2" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.jwkset2" contains 4 keys

  Scenario: A Key Set is available through a service and loaded from an URL
    When the service "jose.key_set.jwkset3" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.jwkset3" contains keys

  Scenario: A Key Set is available through a service and loaded from an URL
    When the service "jose.key_set.jwkset4" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.jwkset4" contains keys

  Scenario: A Rotatable Key Set contains the expected number of keys
    When the service "jose.key_set.auto_signature" should be an object that implements "\Jose\Object\RotatableInterface"
    When the service "jose.key_set.auto_signature" should be an object that implements "\Jose\Object\StorableInterface"
    When the service "jose.key_set.auto_signature" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.auto_signature" contains 5 keys

  Scenario: A Key Set of Key Sets contains the expected number of keys
    When the service "jose.key_set.all_in_one" should be an object that implements "\Jose\Component\KeyManagement\JWKSets"
    When the service "jose.key_set.all_in_one" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.all_in_one" contains 7 keys

  Scenario: A Public Key Set contains the expected number of keys
    When the service "jose.key_set.all_in_one_public" should be an object that implements "\Jose\Object\PublicJWKSet"
    When the service "jose.key_set.all_in_one_public" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.all_in_one_public" contains 7 keys
