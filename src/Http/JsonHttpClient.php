<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Http;

use Bannerstop\Keycloak\Exception\HttpException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * The few JSON requests Keycloak needs, on top of any PSR-18 client.
 *
 * @internal
 */
final class JsonHttpClient
{
    private ClientInterface $client;
    private RequestFactoryInterface $requestFactory;
    private StreamFactoryInterface $streamFactory;

    public function __construct(ClientInterface $client, RequestFactoryInterface $requestFactory, StreamFactoryInterface $streamFactory)
    {
        $this->client = $client;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
    }

    /**
     * @param array<string, scalar> $query
     *
     * @return array<mixed>
     */
    public function get(string $url, array $query = [], ?string $bearerToken = null): array
    {
        if ([] !== $query) {
            $url .= (false === strpos($url, '?') ? '?' : '&') . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
        }
        $request = $this->requestFactory->createRequest('GET', $url)->withHeader('Accept', 'application/json');
        if (null !== $bearerToken) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $bearerToken);
        }

        return $this->send($request);
    }

    /**
     * Posts an application/x-www-form-urlencoded body, as the token endpoint expects it.
     *
     * @param array<string, string> $fields
     *
     * @return array<mixed>
     */
    public function postForm(string $url, array $fields, ?string $basicUser = null, ?string $basicPassword = null): array
    {
        $request = $this->requestFactory->createRequest('POST', $url)
            ->withHeader('Accept', 'application/json')
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streamFactory->createStream(http_build_query($fields, '', '&', PHP_QUERY_RFC1738)));
        if (null !== $basicUser) {
            // RFC 6749 2.3.1: both parts are form-encoded before they are joined
            $credentials = urlencode($basicUser) . ':' . urlencode((string) $basicPassword);
            $request = $request->withHeader('Authorization', 'Basic ' . base64_encode($credentials));
        }

        return $this->send($request);
    }

    /**
     * @return array<mixed>
     */
    private function send(RequestInterface $request): array
    {
        $target = $request->getMethod() . ' ' . $request->getUri()->withQuery('');
        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $exception) {
            throw new HttpException(sprintf('%s failed: %s', $target, $exception->getMessage()), null, $exception);
        }

        $status = $response->getStatusCode();
        try {
            $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            $data = null;
        }
        if ($status < 200 || $status >= 300) {
            $error = is_array($data) && isset($data['error']) && is_string($data['error']) ? $data['error'] : 'no error code';
            throw new HttpException(sprintf('%s returned HTTP %d (%s).', $target, $status, $error), $status);
        }
        if (!is_array($data)) {
            throw new HttpException(sprintf('%s returned no JSON document.', $target), $status);
        }

        return $data;
    }
}
