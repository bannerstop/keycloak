<?php

declare(strict_types=1);

namespace Bannerstop\Keycloak\Policy;

use Bannerstop\Keycloak\Exception\ConfigurationException;
use Bannerstop\Keycloak\Identity;

/**
 * Lets only users with a verified e-mail address of the given domains in.
 * Subdomains are not included, list them explicitly.
 */
final class EmailDomainPolicy implements IdentityPolicy
{
    /** @var string[] */
    private array $domains;

    /**
     * @param string[] $domains
     */
    public function __construct(
        array $domains,
        private bool $requireVerified = true,
    ) {
        $normalized = [];
        foreach ($domains as $domain) {
            $domain = strtolower(trim((string) $domain));
            if ('' === $domain || str_contains($domain, '@')) {
                throw new ConfigurationException(sprintf('"%s" is not an e-mail domain.', $domain));
            }
            $normalized[] = $domain;
        }
        if ([] === $normalized) {
            throw new ConfigurationException('At least one e-mail domain is required.');
        }
        $this->domains = $normalized;
    }

    public function allows(Identity $identity): bool
    {
        if ($this->requireVerified && !$identity->isEmailVerified()) {
            return false;
        }

        return in_array($identity->getEmailDomain(), $this->domains, true);
    }
}
