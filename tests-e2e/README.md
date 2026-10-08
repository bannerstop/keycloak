# End-to-end test

Runs the library against a real Keycloak with the realm in `realm.json`. A
plain curl "browser" fills in the login form; everything else goes through the
library.

```bash
docker network create kc-e2e
docker run -d --name kc-e2e --network kc-e2e --network-alias keycloak \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/realm.json:/opt/keycloak/data/import/realm.json:ro" \
  quay.io/keycloak/keycloak:26.4 start-dev --import-realm

composer install
composer require symfony/http-client   # or php-http/guzzle6-adapter on PHP 7.1
docker run --rm --network kc-e2e -v "$PWD:/app" -w /app php:8.4-cli php run.php
```

The realm, the passwords and the client secret only exist for this test.
