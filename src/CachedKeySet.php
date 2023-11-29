<?php

namespace Firebase\JWT;

use ArrayAccess;
use InvalidArgumentException;
use LogicException;
use OutOfBoundsException;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use RuntimeException;
use UnexpectedValueException;

/**
 * @implements ArrayAccess<string, Key>
 */
class CachedKeySet implements ArrayAccess
{
    /**
     * @var string
     */
    private $jwksUri;
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
     * @var ?int
     */
    private $expiresAfter;
    /**
     * @var ?CacheItemInterface
     */
    private $cacheItem;
    /**
     * @var string
     */
    private $cacheKey;
    /**
     * @var string
     */
    private $cacheKeyPrefix = 'jwks';
    /**
     * @var int
     */
    private $maxKeyLength = 64;
    /**
     * @var bool
     */
    private $rateLimit;
    /**
     * @var string
     */
    private $rateLimitCacheKey;
    /**
     * @var int
     */
    private $maxCallsPerMinute = 10;
    /**
     * @var string|null
     */
    private $defaultAlg;

    public function __construct(
        string $jwksUri,
        ClientInterface $httpClient,
        RequestFactoryInterface $httpFactory,
        CacheItemPoolInterface $cache,
        int $expiresAfter = null,
        bool $rateLimit = false,
        string $defaultAlg = null
    ) {
        $this->jwksUri = $jwksUri;
        $this->httpClient = $httpClient;
        $this->httpFactory = $httpFactory;
        $this->cache = $cache;
        $this->expiresAfter = $expiresAfter;
        $this->rateLimit = $rateLimit;
        $this->defaultAlg = $defaultAlg;
        $this->setCacheKeys();
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
        return JWK::parseKey($this->keySet[$keyId], $this->defaultAlg);
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

    /**
     * @return array<mixed>
     */
    private function formatJwksForCache(string $jwks): array
    {
        $jwks = json_decode($jwks, true);

        if (!isset($jwks['keys'])) {
            throw new UnexpectedValueException('"keys" member must exist in the JWK Set');
        }

        if (empty($jwks['keys'])) {
            throw new InvalidArgumentException('JWK Set did not contain any keys');
        }

        $keys = [];
        foreach ($jwks['keys'] as $k => $v) {
            $kid = isset($v['kid']) ? $v['kid'] : $k;
            $keys[(string) $kid] = $v;
        }

        return $keys;
    }

    private function keyIdExists(string $keyId): bool
    {
	    // Try to load keys from cache
	    $cachedKeySet = $this->getCacheItem();

        if ($cachedKeySet->isHit()) {
            // item found! retrieve it
            $keySet = $cachedKeySet->get();

            // If the cached item is a string, the JWKS response was cached (previous behavior).
            // Parse this into expected format array<kid, jwk> instead.
            if (\is_string($keySet)) {
                $keySet = $this->formatJwksForCache($keySet);
            }

			if (!isset($keySet[$keyId])) {
				return false;
			}
        } else {
			//Can we retrieve a new jwks ?
			if ($this->rateLimitExceeded()) {
				return false;
			}

			//Otherwise, get a refreshed token
			$request = $this->httpFactory->createRequest('GET', $this->jwksUri);
			$jwksResponse = $this->httpClient->sendRequest($request);

			if ($jwksResponse->getStatusCode() !== 200) {
				throw new UnexpectedValueException(
					sprintf('HTTP Error: %d %s for URI "%s"',
						$jwksResponse->getStatusCode(),
						$jwksResponse->getReasonPhrase(),
						$this->jwksUri,
					),
					$jwksResponse->getStatusCode()
				);
			}

			//Save obtained key set
			$keySet = $this->formatJwksForCache((string) $jwksResponse->getBody());
			$cachedKeySet->set($keySet);

	        if ($this->expiresAfter !== null) {
		        $cachedKeySet->expiresAfter($this->expiresAfter);
	        }
	        $this->cache->save($cachedKeySet);

	        //Check keyId presence
	        if (!isset($keySet[$keyId])) {
				return false;
			}
        }

        return true;
    }

    private function rateLimitExceeded(): bool
    {
        if (!$this->rateLimit) {
            return false;
        }

        $cacheItem = $this->cache->getItem($this->rateLimitCacheKey);
        if (!$cacheItem->isHit()) {
            $cacheItem->expiresAfter(1); // # of calls are cached each minute
        }

        $callsPerMinute = (int) $cacheItem->get();
        if (++$callsPerMinute > $this->maxCallsPerMinute) {
            return true;
        }
        $cacheItem->set($callsPerMinute);
        $this->cache->save($cacheItem);
        return false;
    }

    private function getCacheItem(): CacheItemInterface
    {
        if (\is_null($this->cacheItem)) {
            $this->cacheItem = $this->cache->getItem($this->cacheKey);
        }

        return $this->cacheItem;
    }

    private function setCacheKeys(): void
    {
        if (empty($this->jwksUri)) {
            throw new RuntimeException('JWKS URI is empty');
        }

        // ensure we do not have illegal characters
        $key = preg_replace('|[^a-zA-Z0-9_\.!]|', '', $this->jwksUri);

        // add prefix
        $key = $this->cacheKeyPrefix . $key;

        // Hash keys if they exceed $maxKeyLength of 64
        if (\strlen($key) > $this->maxKeyLength) {
            $key = substr(hash('sha256', $key), 0, $this->maxKeyLength);
        }

        $this->cacheKey = $key;

        if ($this->rateLimit) {
            // add prefix
            $rateLimitKey = $this->cacheKeyPrefix . 'ratelimit' . $key;

            // Hash keys if they exceed $maxKeyLength of 64
            if (\strlen($rateLimitKey) > $this->maxKeyLength) {
                $rateLimitKey = substr(hash('sha256', $rateLimitKey), 0, $this->maxKeyLength);
            }

            $this->rateLimitCacheKey = $rateLimitKey;
        }
    }
}
