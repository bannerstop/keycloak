<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Jwt;

use Bannerstop\Keycloak\Exception\HttpException;
use Bannerstop\Keycloak\Exception\InvalidTokenException;
use Bannerstop\Keycloak\KeycloakConfig;
use Bannerstop\Keycloak\Token\Claims;
use Psr\Clock\ClockInterface;

/**
 * Verifies signature, issuer and lifetime of a token, plus the checks that
 * are specific to ID tokens and access tokens.
 */
final class TokenVerifier
{
    /** Keycloak marks ID tokens with typ "ID" and access tokens with typ "Bearer". */
    private const TYPE_ID = 'ID';
    private const TYPE_ACCESS = 'Bearer';
    private const TYPE_LOGOUT = 'Logout';
    private const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
    private readonly ClockInterface $clock;

    public function __construct(
        private readonly KeycloakConfig $config,
        private readonly KeySetProvider $keys,
        ClockInterface $clock,
    ) {
        $this->clock = $clock;
    }

    /**
     * ID token checks of OpenID Connect Core 3.1.3.7.
     *
     * @throws InvalidTokenException
     * @throws HttpException
     */
    public function verifyIdToken(string $token, ?string $nonce): Claims
    {
        $claims = $this->verify($token, self::TYPE_ID);

        $audiences = $claims->getStringList('aud');
        if (!in_array($this->config->getClientId(), $audiences, true)) {
            throw new InvalidTokenException('The ID token was issued for another client.');
        }
        $authorizedParty = $claims->getString('azp');
        if ((count($audiences) > 1 || null !== $authorizedParty) && $authorizedParty !== $this->config->getClientId()) {
            throw new InvalidTokenException('The ID token was issued to another authorized party.');
        }
        if (null === $claims->getInt('iat')) {
            throw new InvalidTokenException('The ID token has no iat claim.');
        }
        if (null !== $nonce && !hash_equals($nonce, (string) $claims->getString('nonce'))) {
            throw new InvalidTokenException('The ID token belongs to another login.');
        }

        return $claims;
    }

    /**
     * Checks an access token presented to an API. The audience must be set
     * explicitly in Keycloak (audience mapper), azp alone is not enough: it
     * only names the client that requested the token.
     *
     * @throws InvalidTokenException
     * @throws HttpException
     */
    public function verifyAccessToken(string $token, string $audience): Claims
    {
        $claims = $this->verify($token, self::TYPE_ACCESS);
        if (!in_array($audience, $claims->getStringList('aud'), true)) {
            throw new InvalidTokenException('The access token was not issued for this audience.');
        }

        return $claims;
    }

    /**
     * Checks an access token that was received from the token endpoint during
     * our own login. Its audience is whatever Keycloak puts in (often only
     * "account"), so the token is bound by azp to this client instead.
     *
     * @throws InvalidTokenException
     * @throws HttpException
     */
    public function verifyOwnAccessToken(string $token): Claims
    {
        $claims = $this->verify($token, self::TYPE_ACCESS);
        if ($claims->getString('azp') !== $this->config->getClientId()) {
            throw new InvalidTokenException('The access token was issued to another client.');
        }

        return $claims;
    }

    /**
     * Logout token checks of OpenID Connect Back-Channel Logout 1.0, 2.6.
     * The events claim keeps ID and access tokens from passing as logout
     * tokens, the jti makes replays detectable (see SessionRevocations).
     *
     * @throws InvalidTokenException
     * @throws HttpException
     */
    public function verifyLogoutToken(string $token): Claims
    {
        $claims = $this->verify($token, self::TYPE_LOGOUT, false);

        if (!in_array($this->config->getClientId(), $claims->getStringList('aud'), true)) {
            throw new InvalidTokenException('The logout token was issued for another client.');
        }
        if (null === $claims->getInt('iat')) {
            throw new InvalidTokenException('The logout token has no iat claim.');
        }
        if (null === $claims->getString('jti')) {
            throw new InvalidTokenException('The logout token has no jti claim.');
        }
        $events = $claims->get('events');
        if (!is_array($events) || !array_key_exists(self::BACKCHANNEL_LOGOUT_EVENT, $events)) {
            throw new InvalidTokenException('The token is not a back-channel logout token.');
        }
        if ($claims->has('nonce')) {
            throw new InvalidTokenException('A logout token must not carry a nonce.');
        }
        if (null === $claims->getString('sub') && null === $claims->getString('sid')) {
            throw new InvalidTokenException('The logout token names neither a user nor a session.');
        }

        return $claims;
    }

    /**
     * @throws InvalidTokenException
     * @throws HttpException
     */
    private function verify(string $token, string $expectedType, bool $requireSubject = true): Claims
    {
        $jwt = Jwt::parse($token);
        $algorithm = Algorithm::tryFrom((string) $jwt->getAlgorithm());
        if (null === $algorithm || !in_array($algorithm, $this->config->getAllowedAlgorithms(), true)) {
            throw new InvalidTokenException(sprintf('The signature algorithm "%s" is not allowed.', (string) $jwt->getAlgorithm()));
        }
        if ($jwt->hasCriticalHeader()) {
            throw new InvalidTokenException('The token has critical header parameters.');
        }
        $key = $this->keys->find($jwt->getKeyId(), $algorithm);
        if (null === $key) {
            throw new InvalidTokenException('The token was signed with an unknown key.');
        }
        if (!$key->verify($algorithm, $jwt->getSigningInput(), $jwt->getSignature())) {
            throw new InvalidTokenException('The token signature is invalid.');
        }

        $claims = new Claims($jwt->getPayload());
        if ($claims->getString('iss') !== $this->config->getIssuer()) {
            throw new InvalidTokenException('The token was issued by another issuer.');
        }
        if ($requireSubject && null === $claims->getString('sub')) {
            throw new InvalidTokenException('The token has no subject.');
        }
        $type = $claims->getString('typ');
        if (null !== $type && 0 !== strcasecmp($type, $expectedType)) {
            throw new InvalidTokenException(sprintf('Expected a token of type "%s", got "%s".', $expectedType, $type));
        }

        $now = $this->clock->now()->getTimestamp();
        $leeway = $this->config->getLeeway();
        $expiresAt = $claims->getInt('exp');
        if (null === $expiresAt) {
            throw new InvalidTokenException('The token has no expiry.');
        }
        if ($expiresAt <= $now - $leeway) {
            throw new InvalidTokenException('The token has expired.');
        }
        $notBefore = $claims->getInt('nbf');
        if (null !== $notBefore && $notBefore > $now + $leeway) {
            throw new InvalidTokenException('The token is not valid yet.');
        }
        $issuedAt = $claims->getInt('iat');
        if (null !== $issuedAt && $issuedAt > $now + $leeway) {
            throw new InvalidTokenException('The token was issued in the future.');
        }

        return $claims;
    }
}
