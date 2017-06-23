Feature: The configuration helper allow developers to create services easily

  Scenario: A Rotatable Key Set created using the configuration helper contains the expected number of keys
    When the service "jose.key_set.from_configuration_helper" should be an object that implements "\Jose\Object\RotatableInterface"
    When the service "jose.key_set.from_configuration_helper" should be an object that implements "\Jose\Object\StorableInterface"
    When the service "jose.key_set.from_configuration_helper" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.from_configuration_helper" contains 2 keys

  Scenario: A Rotatable Key Set created using the configuration helper contains the expected number of keys
    When the service "jose.key_set.all_in_one_from_configuration_helper" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.all_in_one_from_configuration_helper" contains 2 keys

  Scenario: A Rotatable Key Set created using the configuration helper contains the expected number of keys
    When the service "jose.key_set.all_in_one_public_from_configuration_helper" should be an object that implements "\Jose\Component\Core\JWKSetInterface"
    And the keyset in the service "jose.key_set.all_in_one_public_from_configuration_helper" contains 2 keys

  Scenario: Services are available
    And the service "jose.signer.from_configuration_helper" should be an object that implements "\Jose\SignerInterface"
    And the service "jose.verifier.from_configuration_helper" should be an object that implements "\Jose\VerifierInterface"
    And the service "jose.encrypter.from_configuration_helper" should be an object that implements "\Jose\EncrypterInterface"
    And the service "jose.decrypter.from_configuration_helper" should be an object that implements "\Jose\DecrypterInterface"
    And the service "jose.checker.from_configuration_helper" should be an object that implements "\Jose\Checker\CheckerManagerInterface"
    And the service "jose.jwt_loader.from_configuration_helper" should be an object that implements "\Jose\JWTLoaderInterface"
    And the service "jose.jwt_creator.from_configuration_helper" should be an object that implements "\Jose\JWTCreatorInterface"
