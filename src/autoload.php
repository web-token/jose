<?php
/**
 * Created by PhpStorm.
 * User: Álvaro
 * Date: 09/05/2018
 * Time: 3:28
 */

// DECRYPT

require( __DIR__ . "/../assert/Assert.php");
require( __DIR__ . "/../assert/Assertion.php");
require( __DIR__ . "/../assert/AssertionFailedException.php");
require( __DIR__ . "/../assert/InvalidArgumentException.php");

require(__DIR__ . "/../fg/Utility/BigInteger.php");
require(__DIR__ . "/../fg/Utility/BigIntegerGmp.php");
require(__DIR__ . "/../fg/ASN1/Parsable.php");
require(__DIR__ . "/../fg/ASN1/ASNObject.php");
require(__DIR__ . "/../fg/ASN1/Construct.php");
require(__DIR__ . "/../fg/ASN1/Identifier.php");
require(__DIR__ . "/../fg/ASN1/Universal/Sequence.php");
require(__DIR__ . "/../fg/ASN1/Universal/Integer.php");

require(__DIR__ . "/../fg/ASN1/Base128.php");

require(__DIR__ . "/../fg/ASN1/Universal/ObjectIdentifier.php");
require(__DIR__ . "/../fg/ASN1/Universal/NullObject.php");
require(__DIR__ . "/../fg/ASN1/Universal/OctetString.php");

require(__DIR__ . "/../base64url/Base64Url.php");

require("Util/BigInteger.php");

require("Algorithm/JWAInterface.php");
require("Algorithm/KeyEncryptionAlgorithmInterface.php");
require("Algorithm/KeyEncryption/KeyEncryptionInterface.php");

require("Util/Hash.php");
require("Util/RSA.php");

require("Algorithm/KeyEncryption/RSA.php");
require("Algorithm/KeyEncryption/RSAOAEP.php");
require("Algorithm/JWAManagerInterface.php");
require("Algorithm/JWAManager.php");

require("Algorithm/ContentEncryptionAlgorithmInterface.php");

require(__DIR__ . "/../php-aes-gcm/AESGCM.php");

// For decrypt
require("Algorithm/ContentEncryption/AESGCM.php");
require("Algorithm/ContentEncryption/A256GCM.php");

// For encrypt

// RSA-OAEP-256
require("Algorithm/ContentEncryption/AESCBCHS.php");
require("Algorithm/ContentEncryption/A256CBCHS512.php");
require("Algorithm/KeyEncryption/RSAOAEP256.php");

//A256GCMKW
require("Algorithm/KeyEncryption/KeyWrappingInterface.php");
require("Algorithm/KeyEncryption/AESGCMKW.php");
require("Algorithm/KeyEncryption/A256GCMKW.php");

require("Factory/AlgorithmManagerFactory.php");

require("Compression/CompressionInterface.php");
require("Compression/GZip.php");
require("Compression/ZLib.php");
require("Compression/Deflate.php");
require("Compression/CompressionManagerInterface.php");
require("Compression/CompressionManager.php");
require("Factory/CompressionManagerFactory.php");

require("Behaviour/CommonCipheringMethods.php");
require("Behaviour/HasCompressionManager.php");
require("Behaviour/HasJWAManager.php");
require("Behaviour/HasKeyChecker.php");

require("DecrypterInterface.php");
require("Decrypter.php");

require("Object/RecipientInterface.php");
require("Object/Recipient.php");

require("Object/JWTInterface.php");
require("Object/JWT.php");
require("Object/JWEInterface.php");
require("Object/JWE.php");
require("Util/JWELoader.php");

require("Object/BaseJWKSet.php");
require("Object/JWKSetInterface.php");
require("Object/JWKSetPEM.php");
require("Object/JWKSet.php");
require("Object/JWKInterface.php");
require("Object/JWK.php");

require(__DIR__ . "/../fg/ASN1/Universal/BitString.php");

require("KeyConverter/RSAKey.php");
require("KeyConverter/KeyConverter.php");
require("Factory/JWKFactoryInterface.php");
require("Factory/JWKFactory.php");
require("LoaderInterface.php");
require("Loader.php");

// ENCRYPT

require("Behaviour/EncrypterTrait.php");
require("EncrypterInterface.php");
require("Encrypter.php");
require("Factory/JWEFactoryInterface.php");
require("Factory/JWEFactory.php");