# OAUTH2 authenticator for AzureAD

## Requesting additional Graph scopes

By default the class only requests `https://graph.microsoft.com/User.Read`,
enough to resolve the signed-in user's profile for `logon_callback`. If your
app needs to make further Graph calls with the same delegated permissions
(e.g. reading group memberships), request the extra scope(s) before calling
`requestAzureAdCode()`:

```php
->addScope( 'https://graph.microsoft.com/GroupMember.Read.All' )
```

`setScope()` replaces the scope entirely instead of extending it — only use
it if you also want to drop the default `User.Read` scope.

`logon_callback` receives the raw token response as an optional second
argument, so it can use the access token for its own Graph calls within the
same request (there's no second round-trip, and nothing is persisted by this
class — store what you need in `$_SESSION` yourself if it must survive past
`logon_callback`):

```php
function findUser( array $resource, array $tokenAnswer ): bool
{
  // $tokenAnswer['access_token'] -- Bearer token for the scopes granted above
  // $tokenAnswer['expires_in']   -- seconds until it expires
}
```

Existing single-argument `logon_callback` implementations don't need to
change — PHP ignores the extra argument for callables that don't declare it.

## Sample

Where config.php sets the global SETTINGS and logger LOG

```php
<?php declare(strict_types=1);
define( 'ROOT', dirname( __DIR__ ) );
require ROOT . '/config/config.php';
require ROOT . '/vendor/autoload.php';
require ROOT . '/inc/logger.inc.php';

// Assuming LOG contains a Monolog.Logger and SETTINGS contains an array with azure settings.

// dispatch
if( array_key_exists( 'action', $_GET ) ) {
  handleAction();
} else {
  handleCallback();
}
/**
 * Handles the OAuth2 callback after user authentication.
 * This function processes the authorization response from the OAuth2 provider,
 * extracts necessary tokens or parameters, and completes the authentication flow.
 */
function handleCallback() {
    // handle the callback from Azure AD
  (new AzureAuthenticator(
    SETTINGS['aad']['client-id'],
    SETTINGS['aad']['client-secret'],
    'https://' . $_SERVER['SERVER_NAME'] . '/' . basename( $_SERVER['SCRIPT_FILENAME'],
    // LOG,
  )
  ))
    // setup...
    ->setTenantId( SETTINGS['aad']['tennant-id'] )
    ->setLogonCallback( 'findUser' )
    ->setGetStateCallback( 'getState' )
    ->setCheckStateCallback( 'checkState' )

    // go...
    ->handleAuthorizationCode();
}

/**
 * handleAction handle a GET action
 * 
 * @return void
 */
function handleAction(): void
{
  LOG->debug( 'Logon action: ', $_GET );

  switch( $_GET[ 'action' ] ) {

    // unknown action
    default:
      LOG->warning( 'Unknown action: ', [ 'action' => $_GET[ 'action' ] ] );
      exit;

    // attempt to logon
    case 'login':
      try {
        ( new \Kingsoft\Azure\AzureAuthenticator(
          SETTINGS[ 'aad' ][ 'client-id' ],
          SETTINGS[ 'aad' ][ 'client-secret' ],
          'https://' . $_SERVER[ 'SERVER_NAME' ] . '/' . basename( $_SERVER[ 'SCRIPT_FILENAME' ] ),
          LOG,
        ) )
          ->setTenantId( SETTINGS[ 'aad' ][ 'tenant-id' ] )
          ->setLogonCallback( 'findUser' )
          ->setGetStateCallback( 'getState' )
          //->setCheckStateCallback( 'checkState' )
          ->requestAzureAdCode();
      } catch ( \Exception $e ) {
        LOG->error( 'Request Azure Code failed', [ 'message' => $e->getMessage() ] );

        session_destroy();
        http_response_code( 401 );
      }
      // exit to wait for the callback from Azure AD
      exit;

    // logout
    case 'logout':
      LOG->notice( 'Logout', $_SESSION );

      session_destroy();
      $_SESSION = [];

      ( new \Kingsoft\Azure\AzureAuthenticator(
        SETTINGS[ 'aad' ][ 'client-id' ],
        SETTINGS[ 'aad' ][ 'client-secret' ],
        'https://' . $_SERVER[ 'SERVER_NAME' ] . '/' . basename( $_SERVER[ 'SCRIPT_FILENAME' ] ),
        LOG,
      ) )
        ->setTenantId( SETTINGS[ 'aad' ][ 'tenant-id' ] )
        ->logoutAzure( 'https://' . $_SERVER[ 'SERVER_NAME' ] );

      exit;
  }
}

// #MARK: callback functions

/**
 * Create the current state value as a string.
 * @returns {string} The current state value.
 */
function getState(): string
{
  return session_id();
}
/**
 * Checks the validity of the provided state string.
 *
 * @param string $state The state value to validate.
 * @return bool Returns true if the state is valid, false otherwise.
 */
function checkState( string $state ): bool
{
  return session_id() === $state;
}
/**
 * Searches for a user with the provided resource array.
 *
 * @param array $resource The array containing user data to search for.
 * @param array $tokenAnswer The raw token response (access_token, expires_in, ...);
 *   only useful if you requested extra scopes via setScope()/addScope().
 * @return bool Returns true if the user is found, false otherwise.
 */
function findUser( array $resource, array $tokenAnswer = [] ): bool
{
  try {
    // check with database or so if user exists
    // $resource['id'] contains the object-id of the user

    // if( not found do something like ) {
    //   LOG->warning( "not found", [ 'ExternalId' => $resource[ 'id' ] ] );
    //   session_destroy();
    //   http_response_code( 403 );
    //   echo
    //     '<link rel="stylesheet" crossorigin="" href="/assets/static.css">' .
    //     '<article style="text-align:center;">' .
    //     '<h1>Kein Zugang</h1><img src="/assets/kein-zutritt.jpg"/>' .
    //     '<p><a href="https://' . $_SERVER[ 'SERVER_NAME' ] . '">Logout</a> and retry</p>' .
    //     '</article>';

    //   return false;
    // }

    // store required info from $resource in the session var.

    return true;

  } catch ( Exception $e ) {
    // 
    // LOG->error( 'Logon fatal failure', [ 'code' => $resource[ 'id' ], 'message' => $e->getMessage() ] );

    return false;
  }
}
```
