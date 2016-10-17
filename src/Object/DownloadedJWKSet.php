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
use Psr\Cache\CacheItemPoolInterface;

/**
 * Class DownloadedJWKSet.
 */
abstract class DownloadedJWKSet implements JWKSetInterface
{
    use BaseJWKSet;
    use JWKSetPEM;

    /**
     * @var string
     */
    private $url;

    /**
     * @var null|\Psr\Cache\CacheItemPoolInterface
     */
    private $cache;

    /**
     * @var int
     */
    private $ttl;

    /**
     * @var bool
     */
    private $allow_unsecured_connection;

    /**
     * DownloadedJWKSet constructor.
     *
     * @param string                                 $url
     * @param \Psr\Cache\CacheItemPoolInterface|null $cache
     * @param int                                    $ttl
     * @param bool                                   $allow_unsecured_connection
     * @param bool                                   $allow_http_connection
     */
    public function __construct($url, CacheItemPoolInterface $cache = null, $ttl = 86400, $allow_unsecured_connection = false, $allow_http_connection = false)
    {
        Assertion::boolean($allow_unsecured_connection);
        Assertion::boolean($allow_http_connection);
        Assertion::integer($ttl);
        Assertion::min($ttl, 0);
        Assertion::false(false === filter_var($url, FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED | FILTER_FLAG_HOST_REQUIRED), 'Invalid URL.');
        $allowed_protocols = ['https'];
        if (true === $allow_http_connection) {
            $allowed_protocols[] = 'http';
        }
        Assertion::inArray(mb_substr($url, 0, mb_strpos($url, '://', 0, '8bit'), '8bit'), $allowed_protocols, sprintf('The provided sector identifier URI is not valid: scheme must be one of the following: %s.', json_encode($allowed_protocols)));

        $this->url = $url;
        $this->cache = $cache;
        $this->ttl = $ttl;
        $this->allow_unsecured_connection = $allow_unsecured_connection;
    }

    /**
     * {@inheritdoc}
     */
    public function addKey(JWKInterface $key)
    {
        //Not available
    }

    /**
     * {@inheritdoc}
     */
    public function removeKey($index)
    {
        //Not available
    }

    /**
     * @return string
     */
    protected function getContent()
    {
        $cache_key = sprintf('JWKFactory-Content-%s', hash('sha512', $this->url));
        if (null !== $this->cache) {
            $item = $this->cache->getItem($cache_key);
            if (!$item->isHit()) {
                $content = $this->downloadContent();
                $item->set($content);
                if (0 !== $this->ttl) {
                    $item->expiresAfter($this->ttl);
                }
                $this->cache->save($item);

                return $content;
            } else {
                return $item->get();
            }
        }

        return $this->downloadContent();
    }

    /**
     * @throws \InvalidArgumentException
     *
     * @return string
     */
    private function downloadContent()
    {
        $params = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_URL            => $this->url,
        ];
        if (false === $this->allow_unsecured_connection) {
            $params[CURLOPT_SSL_VERIFYPEER] = true;
            $params[CURLOPT_SSL_VERIFYHOST] = 2;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $params);
        $content = curl_exec($ch);
        curl_close($ch);

        Assertion::false(false === $content, 'Unable to get content.');

        return $content;
    }
}
