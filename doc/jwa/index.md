Algorithm Management
====================

# Algorithm Manager

For each cryptographic operation you will perform, you will need at least one algorithm.

The available algorithms depend on the cypher operation to be performed.
Please refer to the [Signed tokens](../jws/index.md) or the [Encrypted tokens](../jwe/index.md) to know more.

Those algorithms are managed by an **Algorithm Manager**.
In the following example, we will create an algorithm manager that will handle two algorithms: `PS256` and `ES512`

```php
<?php

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\ES512;

$algorithm_manager = AlgorithmManager::create([
    new PS256(),
    new ES512(),
]);
```

*It is not possible to set the same algorithm twice in the same algorithm manager.*

# Algorithm Manager Factory

Your application may need several algorithm managers for several use cases.
For example it will send signed events to a platform and issue authentication tokens for registered users.  

To avoid mixing algorithms in one algorithm manager or instantiate several times the algorithms for several algorithm managers,
this framework provides an **Algorithm Manager Factory**.

This factory will create algorithm managers on demand. It also allows the same algorithm to be instantiated multiple times but with different configuration options.

```php
<?php

use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;

$algorithm_manager_factory = new AlgorithmManagerFactory();
$algorithm_manager_factory
    ->add('PS256', new PS256())
    ->add('A128CBC-HS256', new A128CBCHS256())
    ->add('PBES2-HS512+A256KW', new PBES2HS512A256KW())
    ->add('PBES2-HS512+A256KW with custom configuration', new PBES2HS512A256KW(128, 8192))
;
```

The first argument of the method `add` is the alias for the algorithm. **It must be unique**.
As you can see in the example, we added the algorithm `PBES2-HS512+A256KW` twice: with the default configuration and with custom arguments.

Now that our algorithm manager factory is ready, we can create several algorithm managers by passing a list of aliases to the method `create`:

```php
<?php

$signature_algorithm_manager = $algorithm_manager_factory->create(['PS256']);
$encryption_algorithm_manager = $algorithm_manager_factory->create(['A128CBC-HS256', 'PBES2-HS512+A256KW']);
$encryption_algorithm_manager_for_paranoid = $algorithm_manager_factory->create(['A128CBC-HS256', 'PBES2-HS512+A256KW with custom configuration']);
```
