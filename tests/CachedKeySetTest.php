<?php

namespace Firebase\JWT;

use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\CacheItemInterface;
use Prophecy\Argument;
use LogicException;
use OutOfBoundsException;

class CachedKeySetTest extends TestCase
{
    private $testJwkUri = 'httpjwkuri';
    private $testJwkUriKey = 'jwkhttpjwkuri';
    private $testJwk1 = '{"keys": [{"kid":"foo","kty":"RSA","alg":"foo","n":"","e":""}]}';
    private $testJwk2 = '{"keys": [{"kid":"bar","kty":"RSA","alg":"bar","n":"","e":""}]}';

    private $googleRsaUri = 'https://www.googleapis.com/oauth2/v3/certs';
    // private $googleEcUri = 'https://www.gstatic.com/iap/verify/public_key-jwk';

    public function testOffsetSetThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Method not implemented');

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $this->prophesize(CacheItemPoolInterface::class)->reveal()
        );

        $cachedKeySet['foo'] = 'bar';
    }

    public function testOffsetUnsetThrowsException()
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('Method not implemented');

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $this->prophesize(CacheItemPoolInterface::class)->reveal()
        );

        unset($cachedKeySet['foo']);
    }

    public function testOutOfBoundsThrowsException()
    {
        $this->expectException(OutOfBoundsException::class);
        $this->expectExceptionMessage('Key ID not found');

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->getMockHttpClient($this->testJwk1),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );

        // keyID doesn't exist
        $cachedKeySet['bar'];
    }

    public function testWithExistingKeyId()
    {
        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->getMockHttpClient($this->testJwk1),
            $this->getMockHttpFactory(),
            $this->getMockEmptyCache()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertEquals('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testKeyIdIsCached()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn(JWK::parseKeySet(json_decode($this->testJwk1, true)));

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwkUriKey)
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertEquals('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testCachedKeyIdRefresh()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(true);
        $cacheItem->get()
            ->shouldBeCalledOnce()
            ->willReturn(JWK::parseKeySet(json_decode($this->testJwk1, true)));
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwkUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn(true);

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->getMockHttpClient($this->testJwk2), // updated JWK
            $this->getMockHttpFactory(),
            $cache->reveal()
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertEquals('foo', $cachedKeySet['foo']->getAlgorithm());

        $this->assertInstanceOf(Key::class, $cachedKeySet['bar']);
        $this->assertEquals('bar', $cachedKeySet['bar']->getAlgorithm());
    }

    public function testCacheItemWithExpiresAfter()
    {
        $expiresAfter = 10;
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(false);
        $cacheItem->set(Argument::any())
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });
        $cacheItem->expiresAfter($expiresAfter)
            ->shouldBeCalledOnce()
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwkUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->shouldBeCalledOnce();

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->getMockHttpClient($this->testJwk1),
            $this->getMockHttpFactory(),
            $cache->reveal(),
            $expiresAfter
        );
        $this->assertInstanceOf(Key::class, $cachedKeySet['foo']);
        $this->assertEquals('foo', $cachedKeySet['foo']->getAlgorithm());
    }

    public function testJwtVerify()
    {
        $privKey1 = file_get_contents(__DIR__ . '/data/rsa1-private.pem');
        $payload = array('sub' => 'foo', 'exp' => strtotime('+10 seconds'));
        $msg = JWT::encode($payload, $privKey1, 'RS256', 'jwk1');

        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->willReturn(true);
        $cacheItem->get()
            ->willReturn(JWK::parseKeySet(
                json_decode(file_get_contents(__DIR__ . '/data/rsa-jwkset.json'), true)
            ));

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwkUriKey)
            ->willReturn($cacheItem->reveal());

        $cachedKeySet = new CachedKeySet(
            $this->testJwkUri,
            $this->prophesize(ClientInterface::class)->reveal(),
            $this->prophesize(RequestFactoryInterface::class)->reveal(),
            $cache->reveal()
        );

        $result = JWT::decode($msg, $cachedKeySet);

        $this->assertEquals("foo", $result->sub);
    }

    /**
     * @dataProvider provideFullIntegration
     */
    public function testFullIntegration($jwkUri)
    {
        if (!class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            self::markTestSkipped('Guzzle 7 only');
        }
        // Create cache and http objects
        $cache = new TestMemoryCacheItemPool();
        $http = new \GuzzleHttp\Client();
        $factory = new \GuzzleHttp\Psr7\HttpFactory();

        // Determine "kid" dynamically, because these constantly change
        $response = $http->get($jwkUri);
        $json = (string) $response->getBody();
        $keys = json_decode($json, true);
        $kid = $keys['keys'][0]['kid'] ?? null;
        $this->assertNotNull($kid);

        // Instantiate the cached key set
        $cachedKeySet = new CachedKeySet(
            $jwkUri,
            $http,
            $factory,
            $cache
        );

        $this->assertArrayHasKey($kid, $cachedKeySet);
    }

    public function provideFullIntegration()
    {
        return [
            [$this->googleRsaUri],
            // [$this->googleEcUri, 'LYyP2g']
        ];
    }

    private function getMockHttpClient($testJwk)
    {
        $body = $this->prophesize('Psr\Http\Message\StreamInterface');
        $body->__toString()
            ->shouldBeCalledOnce()
            ->willReturn($testJwk);

        $response = $this->prophesize('Psr\Http\Message\ResponseInterface');
        $response->getBody()
            ->shouldBeCalledOnce()
            ->willReturn($body->reveal());

        $http = $this->prophesize(ClientInterface::class);
        $http->sendRequest(Argument::any())
            ->shouldBeCalledOnce()
            ->willReturn($response->reveal());

        return $http->reveal();
    }

    private function getMockHttpFactory()
    {
        $request = $this->prophesize('Psr\Http\Message\RequestInterface');
        $factory = $this->prophesize(RequestFactoryInterface::class);
        $factory->createRequest('get', $this->testJwkUri)
            ->shouldBeCalledOnce()
            ->willReturn($request->reveal());

        return $factory->reveal();
    }

    private function getMockEmptyCache()
    {
        $cacheItem = $this->prophesize(CacheItemInterface::class);
        $cacheItem->isHit()
            ->shouldBeCalledOnce()
            ->willReturn(false);
        $cacheItem->set(Argument::any())
            ->will(function () {
                return $this;
            });

        $cache = $this->prophesize(CacheItemPoolInterface::class);
        $cache->getItem($this->testJwkUriKey)
            ->shouldBeCalledOnce()
            ->willReturn($cacheItem->reveal());
        $cache->save(Argument::any())
            ->willReturn(true);

        return $cache->reveal();
    }
}

/**
 * A cache item pool
 */
final class TestMemoryCacheItemPool implements CacheItemPoolInterface
{
    private $items;
    private $deferredItems;

    public function getItem($key): CacheItemInterface
    {
        return current($this->getItems([$key]));
    }

    public function getItems(array $keys = []): iterable
    {
        $items = [];

        foreach ($keys as $key) {
            $items[$key] = $this->hasItem($key) ? clone $this->items[$key] : new TestMemoryCacheItem($key);
        }

        return $items;
    }

    public function hasItem($key): bool
    {
        return isset($this->items[$key]) && $this->items[$key]->isHit();
    }

    public function clear(): bool
    {
        $this->items = [];
        $this->deferredItems = [];

        return true;
    }

    public function deleteItem($key): bool
    {
        return $this->deleteItems([$key]);
    }

    public function deleteItems(array $keys): bool
    {
        foreach ($keys as $key) {
            unset($this->items[$key]);
        }

        return true;
    }

    public function save(CacheItemInterface $item): bool
    {
        $this->items[$item->getKey()] = $item;

        return true;
    }

    public function saveDeferred(CacheItemInterface $item): bool
    {
        $this->deferredItems[$item->getKey()] = $item;

        return true;
    }

    public function commit(): bool
    {
        foreach ($this->deferredItems as $item) {
            $this->save($item);
        }

        $this->deferredItems = [];

        return true;
    }
}

/**
 * A cache item.
 */
final class TestMemoryCacheItem implements CacheItemInterface
{
    private $key;
    private $value;
    private $expiration;
    private $isHit = false;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function get(): mixed
    {
        return $this->isHit() ? $this->value : null;
    }

    public function isHit(): bool
    {
        if (!$this->isHit) {
            return false;
        }

        if ($this->expiration === null) {
            return true;
        }

        return $this->currentTime()->getTimestamp() < $this->expiration->getTimestamp();
    }

    public function set($value)
    {
        $this->isHit = true;
        $this->value = $value;

        return $this;
    }

    public function expiresAt($expiration)
    {
        $this->expiration = $expiration;
        return $this;
    }

    public function expiresAfter($time)
    {
        $this->expiration = $this->currentTime()->add(new \DateInterval("PT{$time}S"));
        return $this;
    }

    protected function currentTime()
    {
        return new \DateTime('now', new \DateTimeZone('UTC'));
    }
}
