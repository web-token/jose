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

namespace Jose\Component\Core\Encoder;

/**
 * Class StandardJsonEncoder.
 */
final class StandardJsonEncoder implements PayloadEncoderInterface
{
    /**
     * @var int
     */
    private $options;

    /**
     * @var bool
     */
    private $associative;

    /**
     * @var int
     */
    private $depth;

    /**
     * StandardJsonEncoder constructor.
     * See also json_encode and json_decode parameters.
     *
     * @param int  $options
     * @param bool $associative
     * @param int  $depth
     */
    public function __construct(int $options = 0, bool $associative = false, int $depth = 512)
    {
        $this->options = $options;
        $this->associative = $associative;
        $this->depth = $depth;
    }

    /**
     * {@inheritdoc}
     */
    public function encode($payload): string
    {
        return json_encode($payload, $this->options, $this->depth);
    }

    /**
     * {@inheritdoc}
     */
    public function decode(string $payload)
    {
        return json_decode($payload, $this->associative, $this->depth, $this->options);
    }
}
