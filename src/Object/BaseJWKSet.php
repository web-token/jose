<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

use Assert\Assertion;

/**
 * Class BaseJWKSet.
 */
trait BaseJWKSet
{
    /**
     * @var int
     */
    private $position = 0;

    /**
     * @param int $index
     *
     * @return bool
     */
    public function hasKey($index): bool
    {
        return array_key_exists($index, $this->getKeys());
    }

    /**
     * @param int $index
     *
     * @return JWKInterface
     */
    public function getKey($index): JWKInterface
    {
        Assertion::integer($index, 'The index must be a positive integer.');
        Assertion::greaterOrEqualThan($index, 0, 'The index must be a positive integer.');
        Assertion::true($this->hasKey($index), 'Undefined index.');

        return $this->getKeys()[$index];
    }

    /**
     * @return JWKInterface[]
     */
    abstract public function getKeys(): array;

    /**
     * @param JWKInterface $key
     */
    abstract public function addKey(JWKInterface $key);

    /**
     * @param int $index
     */
    abstract public function removeKey($index);

    /**
     * @return array
     */
    public function jsonSerialize(): array
    {
        return ['keys' => array_values($this->getKeys())];
    }

    /**
     * @param int $mode
     *
     * @return int
     */
    public function count($mode = COUNT_NORMAL): int
    {
        return count($this->getKeys(), $mode);
    }

    /**
     * @return JWKInterface|null
     */
    public function current(): ?JWKInterface
    {
        return $this->hasKey($this->position) ? $this->getKey($this->position) : null;
    }

    /**
     * @return int
     */
    public function key(): int
    {
        return $this->position;
    }

    public function next()
    {
        $this->position++;
    }

    public function rewind()
    {
        $this->position = 0;
    }

    /**
     * @return bool
     */
    public function valid(): bool
    {
        return $this->current() instanceof JWKInterface;
    }

    /**
     * @return int
     */
    public function countKeys(): int
    {
        return count($this->getKeys());
    }

    /**
     * @param mixed $offset
     *
     * @return bool
     */
    public function offsetExists($offset): bool
    {
        return $this->hasKey($offset);
    }

    /**
     * @param mixed $offset
     *
     * @return JWKInterface
     */
    public function offsetGet($offset): JWKInterface
    {
        return $this->getKey($offset);
    }

    /**
     * @param mixed $offset
     * @param mixed $value
     */
    public function offsetSet($offset, $value)
    {
        $this->addKey($value);
    }

    /**
     * @param int $offset
     */
    public function offsetUnset($offset)
    {
        $this->removeKey($offset);
    }

    /**
     * @param string      $type
     * @param null|string $algorithm
     * @param array       $restrictions
     *
     * @return null|JWKInterface
     */
    public function selectKey(string $type, ?string $algorithm = null, array $restrictions = []): ?JWKInterface
    {
        Assertion::inArray($type, ['enc', 'sig']);
        Assertion::nullOrString($algorithm);

        $result = [];
        foreach ($this->getKeys() as $key) {
            $ind = 0;

            // Check usage
            $can_use = $this->canKeyBeUsedFor($type, $key);
            if (false === $can_use) {
                continue;
            }
            $ind += $can_use;

            // Check algorithm
            $alg = $this->canKeyBeUsedWithAlgorithm($algorithm, $key);
            if (false === $alg) {
                continue;
            }
            $ind += $alg;

            // Validate restrictions
            if (false === $this->doesKeySatisfyRestrictions($restrictions, $key)) {
                continue;
            }

            // Add to the list with trust indicator
            $result[] = ['key' => $key, 'ind' => $ind];
        }

        //Return null if no key
        if (empty($result)) {
            return null;
        }

        //Sort by trust indicator
        usort($result, [$this, 'sortKeys']);
        //Return the highest trust indicator (first key)
        return $result[0]['key'];
    }

    /**
     * @param string                    $type
     * @param JWKInterface $key
     *
     * @return bool|int
     */
    private function canKeyBeUsedFor(string $type, JWKInterface $key)
    {
        if ($key->has('use')) {
            return $type === $key->get('use') ? 1 : false;
        }
        if ($key->has('key_ops')) {
            return $type === self::convertKeyOpsToKeyUse($key->get('use')) ? 1 : false;
        }

        return 0;
    }

    /**
     * @param null|string               $algorithm
     * @param JWKInterface $key
     *
     * @return bool|int
     */
    private function canKeyBeUsedWithAlgorithm(string $algorithm, JWKInterface $key)
    {
        if (null === $algorithm) {
            return 0;
        }
        if ($key->has('alg')) {
            return $algorithm === $key->get('alg') ? 1 : false;
        }

        return 0;
    }

    /**
     * @param array                     $restrictions
     * @param JWKInterface $key
     *
     * @return bool
     */
    private function doesKeySatisfyRestrictions(array $restrictions, JWKInterface $key): bool
    {
        foreach ($restrictions as $k => $v) {
            if (!$key->has($k) || $v !== $key->get($k)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param string $key_ops
     *
     * @return string
     */
    private static function convertKeyOpsToKeyUse(string $key_ops): string
    {
        switch ($key_ops) {
            case 'verify':
            case 'sign':
                return 'sig';
            case 'encrypt':
            case 'decrypt':
            case 'wrapKey':
            case 'unwrapKey':
                return 'enc';
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported key operation value "%s"', $key_ops));
        }
    }

    /**
     * @param array $a
     * @param array $b
     *
     * @return int
     */
    public function sortKeys(array $a, array $b): int
    {
        if ($a['ind'] === $b['ind']) {
            return 0;
        }

        return ($a['ind'] > $b['ind']) ? -1 : 1;
    }
}
