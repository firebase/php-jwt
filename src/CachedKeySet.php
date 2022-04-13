<?php

namespace Firebase\JWT;

use ArrayAccess;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\CacheItemInterface;
use LogicException;
use OutOfBoundsException;
use RuntimeException;

/**
 * @template-implements ArrayAccess<string, Key>
 */
class CachedKeySet implements ArrayAccess
{
    /**
     * @var string
     */
    private $jwkUri;
    /**
     * @var ClientInterface
     */
    private $httpClient;
    /**
     * @var RequestFactoryInterface
     */
    private $httpFactory;
    /**
     * @var CacheItemPoolInterface
     */
    private $cache;
    /**
     * @var int
     */
    private $expiresAfter;
    /**
     * @var ?CacheItemInterface
     */
    private $cacheItem;
    /**
     * @var array<string, Key>
     */
    private $keySet;
    /**
     * @var string
     */
    private $cacheKey;
    /**
     * @var string
     */
    private $cacheKeyPrefix = 'jwk';
    /**
     * @var int
     */
    private $maxKeyLength = 64;

    public function __construct(
        string $jwkUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $httpFactory,
        CacheItemPoolInterface $cache,
        int $expiresAfter = null
    ) {
        $this->jwkUri = $jwkUri;
        $this->cacheKey = $this->getCacheKey($jwkUri);
        $this->httpClient = $httpClient;
        $this->httpFactory = $httpFactory;
        $this->cache = $cache;
        $this->expiresAfter = $expiresAfter;
    }

    /**
     * @param string $keyId
     * @return Key
     */
    public function offsetGet($keyId): Key
    {
        if (!$this->keyIdExists($keyId)) {
            throw new OutOfBoundsException('Key ID not found');
        }
        return $this->keySet[$keyId];
    }

    /**
     * @param string $keyId
     * @return bool
     */
    public function offsetExists($keyId): bool
    {
        return $this->keyIdExists($keyId);
    }

    /**
     * @param string $offset
     * @param Key $value
     */
    public function offsetSet($offset, $value): void
    {
        throw new LogicException('Method not implemented');
    }

    /**
     * @param string $offset
     */
    public function offsetUnset($offset): void
    {
        throw new LogicException('Method not implemented');
    }

    private function keyIdExists(string $keyId): bool
    {
        $keySetToCache = null;
        if (null === $this->keySet) {
            $item = $this->getCacheItem();
            // Try to load keys from cache
            if ($item->isHit()) {
                // item found! Return it
                $this->keySet = $item->get();
            }
        }

        if (!isset($this->keySet[$keyId])) {
            $request = $this->httpFactory->createRequest('get', $this->jwkUri);
            $jwkResponse = $this->httpClient->sendRequest($request);
            $jwk = json_decode((string) $jwkResponse->getBody(), true);
            $this->keySet = $keySetToCache = JWK::parseKeySet($jwk);

            if (!isset($this->keySet[$keyId])) {
                return false;
            }
        }

        if ($keySetToCache) {
            $item = $this->getCacheItem();
            $item->set($keySetToCache);
            if ($this->expiresAfter) {
                $item->expiresAfter($this->expiresAfter);
            }
            $this->cache->save($item);
        }

        return true;
    }

    private function getCacheItem(): CacheItemInterface
    {
        if (is_null($this->cacheItem)) {
            $this->cacheItem = $this->cache->getItem($this->cacheKey);
        }

        return $this->cacheItem;
    }

    private function getCacheKey(string $jwkUri): string
    {
        if (empty($jwkUri)) {
            throw new RuntimeException('JWK URI is empty');
        }

        // ensure we do not have illegal characters
        $key = preg_replace('|[^a-zA-Z0-9_\.!]|', '', $jwkUri);

        // add prefix
        $key = $this->cacheKeyPrefix . $key;

        // Hash keys if they exceed $maxKeyLength of 64
        if (strlen($key) > $this->maxKeyLength) {
            $key = substr(hash('sha256', $key), 0, $this->maxKeyLength);
        }

        return $key;
    }
}
