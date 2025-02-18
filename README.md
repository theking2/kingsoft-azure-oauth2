# OAUTH2 authenticator for AzureAD

## Sample

Where config.php sets the global SETTINGS and logger LOG

```php
<?php declare(strict_types=1);
define( 'ROOT', dirname( __DIR__ ) );
require ROOT . '/config/config.php';
require ROOT . '/vendor/autoload.php';
require ROOT . '/inc/logger.inc.php';

if( array_key_exists( 'action', $_GET ) ) {
  handleAction();
} else {
  // handle the callback from Azure AD
  (new AzureAuthenticator(
    SETTINGS['aad']['client-id'],
    SETTINGS['aad']['client-secret'],
    'https://' . $_SERVER['SERVER_NAME'] . '/' . basename( $_SERVER['SCRIPT_FILENAME'] )
  ))
    ->setTennantId( SETTINGS['aad']['tennant-id'] )
    ->setLogonCallback( 'findUser' )
    ->setGetStateCallback( 'getState' )
    ->setCheckStateCallback( 'checkState' )
    ->handleAuthorizationCode();
}
```