<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2017 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Component\Core;

use Assert\Assertion;
use Jose\Component\KeyManagement\KeyConverter\ECKey;
use Jose\Component\KeyManagement\KeyConverter\RSAKey;

/**
 * Class JWKSet.
 */
final class JWKSet implements \Countable, \Iterator, \JsonSerializable, \ArrayAccess
{
    /**
     * @var array
     */
    private $keys = [];

    public function __construct(array $keys = [])
    {
        if (array_key_exists('keys', $keys)) {
            foreach ($keys['keys'] as $value) {
                $this->addKey(JWK::create($value));
            }
        }
    }

    /**
     * Returns all keys in the key set.
     *
     * @return JWK[] An array of keys stored in the key set
     */
    public function getKeys(): array
    {
        return $this->keys;
    }

    /**
     * Add key in the key set.
     *
     * @param JWK $key A key to store in the key set
     */
    public function addKey(JWK $key)
    {
        $this->keys[] = $key;
    }

    /**
     * Remove key from the key set.
     *
     * @param int $key Key to remove from the key set
     */
    public function removeKey(int $key)
    {
        if (isset($this->keys[$key])) {
            unset($this->keys[$key]);
        }
    }

    /**
     * @var int
     */
    private $position = 0;

    /**
     * @param int $index
     *
     * @return bool
     */
    public function hasKey(int $index): bool
    {
        return array_key_exists($index, $this->getKeys());
    }

    /**
     * @param int $index
     *
     * @return JWK
     */
    public function getKey(int $index): JWK
    {
        Assertion::greaterOrEqualThan($index, 0, 'The index must be a positive integer.');
        Assertion::true($this->hasKey($index), 'Undefined index.');

        return $this->getKeys()[$index];
    }

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
     * @return JWK|null
     */
    public function current(): ?JWK
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
        ++$this->position;
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
        return $this->current() instanceof JWK;
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
     * @return JWK
     */
    public function offsetGet($offset): JWK
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
     * @param string      $type         Must be 'sig' (signature) or 'enc' (encryption)
     * @param string|null $algorithm    Specifies the algorithm to be used
     * @param array       $restrictions More restrictions such as 'kid' or 'kty'
     *
     * @return JWK|null
     */
    public function selectKey(string $type, ?string $algorithm = null, array $restrictions = []): ?JWK
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
     * @param string $type
     * @param JWK    $key
     *
     * @return bool|int
     */
    private function canKeyBeUsedFor(string $type, JWK $key)
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
     * @param null|string $algorithm
     * @param JWK         $key
     *
     * @return bool|int
     */
    private function canKeyBeUsedWithAlgorithm(?string $algorithm, JWK $key)
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
     * @param array $restrictions
     * @param JWK   $key
     *
     * @return bool
     */
    private function doesKeySatisfyRestrictions(array $restrictions, JWK $key): bool
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

    /**
     * Returns RSA/EC keys in the key set into PEM format
     * Note that if the key set contains other key types (none, oct, OKP...), they will not be part of the result.
     * If keys have a key ID, it is used as index.
     *
     * @return string[]
     */
    public function toPEM(): array
    {
        $keys = $this->getKeys();
        $result = [];

        foreach ($keys as $key) {
            if (!in_array($key->get('kty'), ['RSA', 'EC'])) {
                continue;
            }

            $pem = $this->getPEM($key);
            if ($key->has('kid')) {
                $result[$key->get('kid')] = $pem;
            } else {
                $result[] = $pem;
            }
        }

        return $result;
    }

    /**
     * @param JWK $key
     *
     * @return string
     */
    private function getPEM(JWK $key): string
    {
        switch ($key->get('kty')) {
            case 'RSA':
                return (new RSAKey($key))->toPEM();
            case 'EC':
                return (new ECKey($key))->toPEM();
            default:
                throw new \InvalidArgumentException('Unsupported key type.');
        }
    }
}
