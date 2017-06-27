Custom Compression Method
=========================

The [spomky-Labs/jose](https://github.com/Spomky-Labs/jose) library provides three compression methods:
- [x] `DEF`: Deflate
- [x] `ZLIB`: ZLib (not described in the RFCs, for internal use only)
- [x] `GZ`: GZip (not described in the RFCs, for internal use only)

But you may need to use your own method (e.g. using 7ZIP, LZMA...).

In the following example, we will create a custom method that uses a (non-existent) `method_compress` and `method_decompress` PHP functions.

# Create it!

First, you have to implement the interface `Jose\Compression\CompressionInterface`.

```php
<?php

namespace AppBundle\Compression;

use Jose\Compression\CompressionInterface;

final class MyCompressionMethod implements CompressionInterface
{
    /**
     * {@inheritdoc}
     */
    public function getMethodName()
    {
         return 'CUSTOM'; // The name of our algorithm
    }
    
    /**
     * {@inheritdoc}
     */
    public function compress($data)
    {
        return method_compress($data);
    }
    
    /**
     * {@inheritdoc}
     */
    public function uncompress($data)
    {
        return method_decompress($data);
    }
}
```

# Add it!

Now we have a new algorithm, we have to create a tagged service that will be added to the algorithm manager algorithm list.

```xml
<?xml version="1.0" ?>

<container xmlns="http://symfony.com/schema/dic/services"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://symfony.com/schema/dic/services http://symfony.com/schema/dic/services/services-1.0.xsd">

    <services>
        <service id="app.compression.my_method" class="AppBundle\Compression\MyCompressionMethod" public="false">
            <tag name="jose.compression" />
        </service>
    </services>
</container>
```

# Use it!

Now you can use your compression method with your encrypters or decrypters

```yml
jose:
    decrypters:
        DECRYPTER1: # ID of the Decrypter. Must be unique
            ...
            compression_methods: # A list of compression methods (see below for the complete list)
                - 'CUSTOM' # Our custom method. This name is the same as returned by the 'getMethodName' method
```
