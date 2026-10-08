<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Tests\Fixtures;

use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class FakeHttpClient implements ClientInterface
{
    /** @var array<string, array<int, callable|array{0: int, 1: mixed}>> */
    private $routes = [];

    /** @var RequestInterface[] */
    public $requests = [];

    /**
     * @param callable|array{0: int, 1: mixed} $response a [status, json] pair or a callable(RequestInterface): array
     */
    public function on(string $method, string $url, $response): self
    {
        $this->routes[$method . ' ' . $url][] = $response;

        return $this;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        $key = $request->getMethod() . ' ' . $request->getUri()->withQuery('');
        if (!isset($this->routes[$key]) || [] === $this->routes[$key]) {
            return new Response(404, [], json_encode(['error' => 'not_found']));
        }
        // The last registered response is repeated, earlier ones are used once.
        $response = count($this->routes[$key]) > 1 ? array_shift($this->routes[$key]) : $this->routes[$key][0];
        if (is_callable($response)) {
            $response = $response($request);
        }

        return new Response($response[0], ['Content-Type' => 'application/json'], json_encode($response[1]));
    }

    /**
     * @return RequestInterface[]
     */
    public function requestsTo(string $method, string $url): array
    {
        return array_values(array_filter($this->requests, static function (RequestInterface $request) use ($method, $url): bool {
            return $request->getMethod() === $method && (string) $request->getUri()->withQuery('') === $url;
        }));
    }
}
