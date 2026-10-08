<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Discovery;

use Bannerstop\Keycloak\Exception\HttpException;

/**
 * The parts of the OpenID Provider discovery document this library uses.
 */
final class ProviderMetadata
{
    /** @var string */
    private $issuer;

    /** @var string */
    private $authorizationEndpoint;

    /** @var string */
    private $tokenEndpoint;

    /** @var string|null */
    private $userinfoEndpoint;

    /** @var string|null */
    private $endSessionEndpoint;

    /** @var string */
    private $jwksUri;

    /** @var string|null */
    private $revocationEndpoint;

    /** @var bool */
    private $issuerParameterSupported;

    public function __construct(
        string $issuer,
        string $authorizationEndpoint,
        string $tokenEndpoint,
        string $jwksUri,
        ?string $userinfoEndpoint = null,
        ?string $endSessionEndpoint = null,
        ?string $revocationEndpoint = null,
        bool $issuerParameterSupported = false
    ) {
        $this->issuer = $issuer;
        $this->authorizationEndpoint = $authorizationEndpoint;
        $this->tokenEndpoint = $tokenEndpoint;
        $this->jwksUri = $jwksUri;
        $this->userinfoEndpoint = $userinfoEndpoint;
        $this->endSessionEndpoint = $endSessionEndpoint;
        $this->revocationEndpoint = $revocationEndpoint;
        $this->issuerParameterSupported = $issuerParameterSupported;
    }

    /**
     * @param array<mixed> $document
     */
    public static function fromArray(array $document): self
    {
        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $required) {
            if (!isset($document[$required]) || !is_string($document[$required]) || '' === $document[$required]) {
                throw new HttpException(sprintf('The discovery document has no %s.', $required));
            }
        }

        $optional = static function (string $name) use ($document): ?string {
            return isset($document[$name]) && is_string($document[$name]) && '' !== $document[$name] ? $document[$name] : null;
        };

        return new self(
            $document['issuer'],
            $document['authorization_endpoint'],
            $document['token_endpoint'],
            $document['jwks_uri'],
            $optional('userinfo_endpoint'),
            $optional('end_session_endpoint'),
            $optional('revocation_endpoint'),
            true === ($document['authorization_response_iss_parameter_supported'] ?? false)
        );
    }

    /**
     * @return array<string, string|null>
     */
    public function toArray(): array
    {
        return [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->authorizationEndpoint,
            'token_endpoint' => $this->tokenEndpoint,
            'jwks_uri' => $this->jwksUri,
            'userinfo_endpoint' => $this->userinfoEndpoint,
            'end_session_endpoint' => $this->endSessionEndpoint,
            'revocation_endpoint' => $this->revocationEndpoint,
            'authorization_response_iss_parameter_supported' => $this->issuerParameterSupported,
        ];
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function getAuthorizationEndpoint(): string
    {
        return $this->authorizationEndpoint;
    }

    public function getTokenEndpoint(): string
    {
        return $this->tokenEndpoint;
    }

    public function getJwksUri(): string
    {
        return $this->jwksUri;
    }

    public function getUserinfoEndpoint(): ?string
    {
        return $this->userinfoEndpoint;
    }

    public function getEndSessionEndpoint(): ?string
    {
        return $this->endSessionEndpoint;
    }

    public function getRevocationEndpoint(): ?string
    {
        return $this->revocationEndpoint;
    }

    /**
     * Whether the provider names itself in every authorization response
     * (RFC 9207). Then a callback without "iss" must be rejected.
     */
    public function isIssuerParameterSupported(): bool
    {
        return $this->issuerParameterSupported;
    }
}
