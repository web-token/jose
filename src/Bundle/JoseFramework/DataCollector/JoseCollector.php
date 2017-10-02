<?php

declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Bundle\JoseFramework\DataCollector;

use Jose\Component\Core\AlgorithmInterface;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Algorithm\KeyEncryptionAlgorithmInterface;
use Jose\Component\Encryption\Compression\CompressionMethodManagerFactory;
use Jose\Component\Signature\Algorithm\SignatureAlgorithmInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;

final class JoseCollector extends DataCollector
{
    /**
     * @var AlgorithmManagerFactory
     */
    private $algorithmManagerFactory;

    /**
     * @var CompressionMethodManagerFactory
     */
    private $compressionMethodManagerFactory;

    /**
     * JoseCollector constructor.
     *
     * @param AlgorithmManagerFactory         $algorithmManagerFactory
     * @param CompressionMethodManagerFactory $compressionMethodManagerFactory
     */
    public function __construct(AlgorithmManagerFactory $algorithmManagerFactory, CompressionMethodManagerFactory $compressionMethodManagerFactory)
    {
        $this->algorithmManagerFactory = $algorithmManagerFactory;
        $this->compressionMethodManagerFactory = $compressionMethodManagerFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function collect(Request $request, Response $response, \Exception $exception = null)
    {
        $aliases = $this->algorithmManagerFactory->aliases();
        $algorithmManager = $this->algorithmManagerFactory->create($aliases);
        $this->data = ['algorithms' => []];
        $signatureAlgorithms = 0;
        $keyEncryptionAlgorithms = 0;
        $contentEncryptionAlgorithms = 0;
        foreach ($algorithmManager->list() as $alias) {
            $algorithm = $algorithmManager->get($alias);
            $type = $this->getAlgorithmType($algorithm, $signatureAlgorithms, $keyEncryptionAlgorithms, $contentEncryptionAlgorithms);
            if (!array_key_exists($type, $this->data['algorithms'])) {
                $this->data['algorithms'][$type] = [];
            }
            $this->data['algorithms'][$type][$alias] = [
                'name' => $algorithm->name(),
            ];
        }

        $this->data['types'] = [
            'signature' => $signatureAlgorithms,
            'key_encryption' => $keyEncryptionAlgorithms,
            'content_encryption' => $contentEncryptionAlgorithms,
        ];

        $aliases = $this->compressionMethodManagerFactory->aliases();
        $cmm = $this->compressionMethodManagerFactory->create($aliases);
        dump($cmm);
    }

    /**
     * @return array
     */
    public function getAlgorithmDetails(): array
    {
        return $this->data['algorithms'];
    }

    /**
     * @return int
     */
    public function countSignatureAlgorithms(): int
    {
        return $this->data['types']['signature'];
    }

    /**
     * @return int
     */
    public function countKeyEncryptionAlgorithms(): int
    {
        return $this->data['types']['key_encryption'];
    }

    /**
     * @return int
     */
    public function countContentEncryptionAlgorithms(): int
    {
        return $this->data['types']['content_encryption'];
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'jose_collector';
    }

    private function getAlgorithmType(AlgorithmInterface $algorithm, int &$signatureAlgorithms, int &$keyEncryptionAlgorithms, int &$contentEncryptionAlgorithms): string
    {
        switch (true) {
            case $algorithm instanceof SignatureAlgorithmInterface:
                $signatureAlgorithms++;

                return 'Signature';
            case $algorithm instanceof KeyEncryptionAlgorithmInterface:
                $keyEncryptionAlgorithms++;

                return 'Key Encryption';
            case $algorithm instanceof ContentEncryptionAlgorithmInterface:
                $contentEncryptionAlgorithms++;

                return 'Content Encryption';
            default:
                return 'Unknown';
        }
    }
}
