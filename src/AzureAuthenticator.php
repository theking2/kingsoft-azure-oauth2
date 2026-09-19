<?php declare(strict_types=1);
namespace Kingsoft\Azure;

use Kingsoft\Http\StatusCode;
/**
 * oauth2 Azure Authentication and Authorization (Graph)
 * the client_id needs access to Graph to lookup the user details, specifically the email and id
 * After success the logon callback is called to implement post logon actions
 */
class AzureAuthenticator
{
  private const MSONLINE_URL  = 'https://login.microsoftonline.com/';
  private const MSGRAPH_SCOPE = 'https://graph.microsoft.com/User.Read';
  private const MSGRAPH_URL   = 'https://graph.microsoft.com/v1.0/me/';

  /**
   * __construct
   * @param $client_id     Azure AD client id
   * @param $client_secret Azure AD client secret
   * @param $redirect_url Azure AD redirect url
   * @param \Psr\Log\LoggerInterface $logger optional logger
   *
   * Make sure to use the setters for the callbacks and tenant_id if required
   */
  public function __construct(
    readonly string $client_id,
    readonly string $client_secret,
    readonly string $redirect_url,
    readonly \Psr\Log\LoggerInterface $logger = new \Psr\Log\NullLogger()
  ) {
    $this->logger->debug( 'AzureAuthenticator loaded' );
  }
  private string $tenant_id = 'common';
  public function setTenantId( string $tenant_id ): self
  {
    $this->tenant_id = $tenant_id;
    return $this;
  }

  private const PKCE_SESSION_KEY = '_azure_pkce_code_verifier';

  private bool $use_pkce     = true;
  private string $pkce_method = 'S256';
  /**
   * MARK: PKCE
   * Enable/disable PKCE (RFC 7636) and pick the challenge method. Enabled with
   * `S256` by default since it costs nothing extra and hardens the code
   * exchange against interception -- disable only if the registered Azure AD
   * app rejects the extra `code_challenge*` parameters.
   * The verifier is stored in `$_SESSION` between requestAzureAdCode() and
   * handleAuthorizationCode() because a fresh instance of this class is
   * created for each leg of the flow.
   */
  public function setPkce( bool $enabled, string $method = 'S256' ): self
  {
    if( !in_array( $method, ['S256', 'plain'], true ) ) {
      throw new \InvalidArgumentException( 'PKCE method must be S256 or plain' );
    }
    $this->use_pkce    = $enabled;
    $this->pkce_method = $method;
    return $this;
  }

  private string $scope = self::MSGRAPH_SCOPE;
  /**
   * MARK: Scope
   * Replace the requested scope entirely. Defaults to `User.Read` only, which is
   * enough to resolve the signed-in user's Graph profile for logon_callback but
   * nothing else -- pass a space-separated scope string to ask for more (e.g. to
   * later make additional Graph calls with the token handed to logon_callback).
   * @see addScope() to extend the default scope instead of replacing it.
   */
  public function setScope( string $scope ): self
  {
    $this->scope = $scope;
    return $this;
  }
  /**
   * Add one or more space-separated scopes to whatever is currently requested,
   * without disturbing the default `User.Read` scope this class needs internally.
   */
  public function addScope( string $scope ): self
  {
    $scopes      = array_filter( explode( ' ', $this->scope . ' ' . $scope ) );
    $this->scope = implode( ' ', array_unique( $scopes ) );
    return $this;
  }
  // #MARK: Callbacks
  private ?string $get_state_callback = null;
  public function setGetStateCallback( string $callback ): self
  {
    $this->get_state_callback = $callback;
    return $this;
  }
  private ?string $logon_callback = null;
  public function setLogonCallback( string $callback ): self
  {
    $this->logon_callback = $callback;
    return $this;
  }
  private ?string $check_state_callback = null;
  public function setCheckStateCallback( string $callback ): self
  {
    $this->check_state_callback = $callback;
    return $this;
  }


  /**
   * MARK: Authorized
   * received an authorization code from Azure AD
   * use this to
   * 1) redeem this code for an access token
   * 2) use the Bearer access token for Graph and get user info (most importantly Object-ID)
   * 3) store user info in session
   * 4) load the associated user from the user table
   *    if this user object-id is not known to us send a 403, unset session
   * 5) redirect to /, user_check.php will handle future authorization
   *
   */
  public function handleAuthorizationCode(): void
  {
    if( !is_callable( $this->logon_callback ) ) {
      throw new \LogicException( 'logon_callback must be set via setLogonCallback() before calling handleAuthorizationCode().' );
    }

    if( isset( $_POST['error'] ) ) {
      $this->handleError( $_POST['error'] );
    }

    if( !$this->isStateValid( $_POST['state'] ?? '' ) ) {
      throw new \RuntimeException( 'State mismatch detected.' );
    }

    $tokenAnswer  = $this->getAccessToken( $_POST['code'] ?? '' );
    $userResource = $this->getUserResource( $tokenAnswer['access_token'] );

    if( !$this->processLogon( $userResource, $tokenAnswer ) ) {
      session_destroy();
      throw new \RuntimeException( 'Logon error: user not recognized.' );
    }

    $this->logger->debug( 'Redirect to /', [
      'userPrincipalName' => $userResource['userPrincipalName'],
      'displayName'       => $userResource["displayName"]
    ] );

    header( 'Location: /' );
    exit();
  }

  // #MARK: Helpers for Authorization
  private function handleError( string $error ): void
  {
    $this->logger->alert( 'Received error', ['error' => $error] );
    http_response_code( StatusCode::BadGateway->value );
    exit();
  }
  private function isStateValid( string $state ): bool
  {
    return is_callable( $this->check_state_callback ) && call_user_func( $this->check_state_callback, $state );
  }

  /**
   * @param array $tokenAnswer the raw token response (access_token, scope,
   *   expires_in, ext_expires_in, token_type, and refresh_token if requested via
   *   `offline_access` scope) -- forwarded to logon_callback so a consumer that
   *   requested extra scopes via setScope()/addScope() can make its own Graph
   *   calls during this same request, without a second token round-trip.
   *   Existing single-argument logon_callback implementations keep working
   *   unchanged; PHP ignores the extra argument for callables that don't declare
   *   a second parameter.
   */
  private function processLogon( array $userResource, array $tokenAnswer ): bool
  {
    $this->logger->info( 'AD User logged on', [
      'userPrincipalName' => $userResource['userPrincipalName'],
      'displayName'       => $userResource["displayName"]
    ] );

    if( !call_user_func( $this->logon_callback, $userResource, $tokenAnswer ) ) {
      $this->logger->alert( 'Logon error', [
        'userPrincipalName' => $userResource['userPrincipalName'],
        'displayName'       => $userResource["displayName"],
        'id'                => $userResource['id']
      ] );
      http_response_code( StatusCode::Forbidden->value );
      exit();
    }

    return true;
  }

  /**
   * Redirect the user to the Microsoft logout endpoint and then to the given URL.
   *
   * **Security notice:** `$redirectUrl` must be a trusted, application-controlled
   * value (e.g. a hard-coded URL or one taken from your own configuration).
   * Never pass a value that originates from user input (`$_GET`, `$_POST`, …).
   * Although Microsoft validates `post_logout_redirect_uri` against the
   * registered redirect URIs for the app, passing an unvalidated caller-supplied
   * value creates an open-redirect vector if that validation is ever loosened or
   * misconfigured.
   *
   * @param string $redirectUrl Trusted URL to redirect to after logout.
   *                            Must not be derived from user-supplied input.
   * @return never
   */
  public function logoutAzure( string $redirectUrl ): never
  {
    $logout_url = self::MSONLINE_URL . $this->tenant_id . "/oauth2/v2.0/logout?post_logout_redirect_uri=$redirectUrl";
    header( "Location: $logout_url" );
    exit;
  }

  /**
   * MARK: Handle a POST from Azure AD
   * Redirects to Azure AD for authorization
   */
  public function requestAzureAdCode(): never
  {
    $state  = $this->get_state_callback ? call_user_func( $this->get_state_callback ) : session_id();
    $params = [
      'client_id'     => $this->client_id,
      'scope'         => $this->scope,
      'redirect_uri'  => $this->redirect_url,
      'response_mode' => 'form_post',
      'response_type' => 'code',
      'state'         => $state,
    ];

    if( $this->use_pkce ) {
      $verifier                         = self::generateCodeVerifier();
      $_SESSION[self::PKCE_SESSION_KEY] = $verifier;
      $params['code_challenge']         = $this->codeChallengeFor( $verifier );
      $params['code_challenge_method']  = $this->pkce_method;
    }

    $this->logger->debug( 'Redirect to Azure AD authorizer', ['url' => $this->redirect_url, 'state' => self::shorten( $state )] );
    $login_url = $this->getAuthUrl();
    header( 'Location: ' . $login_url . '?' . http_build_query( $params ) );
    // we hear back in handleAuthorizationCode
    exit;
  }

  /**
   * Testing only
   * @return void
   */
  public function dryRun(): void
  {
    $this->logger->debug( 'Dry run' );
    $state = $this->get_state_callback ? call_user_func( $this->get_state_callback ) : session_id();
    $valid = $this->check_state_callback ? call_user_func( $this->check_state_callback, $state ) : true;
    $this->logger->debug( 'State validity', ['state' => self::shorten( $state ), 'valid' => $valid] );
    $params = [
      'client_id'     => $this->client_id,
      'scope'         => $this->scope,
      'redirect_uri'  => $this->redirect_url,
      'response_mode' => 'form_post',
      'response_type' => 'code',
      'state'         => $state,
    ];
    if( $this->use_pkce ) {
      $verifier                        = self::generateCodeVerifier();
      $params['code_challenge']        = $this->codeChallengeFor( $verifier );
      $params['code_challenge_method'] = $this->pkce_method;
    }
    $this->logger->debug( 'Params', $params );
  }


  // #MARK: Call Graph

  /**
   * getUserResource from graph
   * @param $access_token received from AD to access graph
   * @throws \RuntimeException if the response is not JSON
   */
  private function getUserResource( string $access_token ): array
  {
    $this->logger->debug( 'Getting user resource from Graph', ['access token' => self::shorten( $access_token, 15 )] );
    /* get user info, using the access token as */
    return $this->sendGet( AzureAuthenticator::MSGRAPH_URL, [], "Bearer $access_token" )
      ?? throw new \RuntimeException( 'No user resource' );
  }
  /**
   * getAccessToken
   * Only accept bearer type tokens
   * @param $authorization_code received from AD to access graph
   * @return array the raw token response (access_token, scope, token_type,
   *   expires_in, ext_expires_in, and refresh_token if `offline_access` was
   *   requested via setScope()/addScope())
   * @throws \RuntimeException if the response is not JSON
   */
  private function getAccessToken( string $authorization_code ): array
  {
    $this->logger->debug( 'Getting access token', ['authorization_code' => self::shorten( $authorization_code, 15 )] );

    /* Request token from Azure AD tokenizer */
    $token_url = $this->getTokenUrl();

    $params = [
      'client_id'     => $this->client_id,
      'client_secret' => $this->client_secret,
      'scope'         => $this->scope,
      'redirect_uri'  => $this->redirect_url,
      'grant_type'    => 'authorization_code',
      'code'          => $authorization_code,
    ];

    if( $this->use_pkce ) {
      $verifier = $_SESSION[self::PKCE_SESSION_KEY] ?? '';
      unset( $_SESSION[self::PKCE_SESSION_KEY] );
      if( $verifier === '' ) {
        throw new \RuntimeException( 'PKCE code verifier missing from session; requestAzureAdCode() must run first in the same session.' );
      }
      $params['code_verifier'] = $verifier;
    }

    // sendPost() throws AzureOAuthException itself on a structured Azure AD
    // error response, so $answer here is always a well-formed success body.
    $answer = $this->sendPost( $token_url, $params );

    if( $answer['token_type'] !== 'Bearer' ) {
      $this->logger->critical( "Wrong token type", ['token_type' => $answer['token_type']] );
      http_response_code( StatusCode::BadGateway->value );
      throw new \RuntimeException( 'Wrong token type' );
    }
    $this->logger->debug( 'Got access token',
      [
        "scope"          => $answer['scope'],
        "token_type"     => $answer['token_type'],
        "expires_in"     => $answer['expires_in'],
        "ext_expires_in" => $answer['ext_expires_in']
      ]
    );
    if( !isset( $answer['access_token'] ) ) {
      throw new \RuntimeException( 'No access token' );
    }
    return $answer;
  }

  // #MARK: helpers
  private function getTokenUrl(): string
  {
    return AzureAuthenticator::MSONLINE_URL . $this->tenant_id . "/oauth2/v2.0/token";
  }

  private function getAuthUrl(): string
  {
    return AzureAuthenticator::MSONLINE_URL . $this->tenant_id . "/oauth2/v2.0/authorize";
  }
  /**
   * RFC 7636 base64url encoding: base64 with URL-safe alphabet and no padding.
   */
  private static function base64UrlEncode( string $data ): string
  {
    return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
  }

  /**
   * generateCodeVerifier
   * 64 random bytes -> ~86 base64url characters, within the 43-128 range RFC 7636 requires.
   */
  private static function generateCodeVerifier(): string
  {
    return self::base64UrlEncode( random_bytes( 64 ) );
  }

  private function codeChallengeFor( string $verifier ): string
  {
    return $this->pkce_method === 'S256'
      ? self::base64UrlEncode( hash( 'sha256', $verifier, true ) )
      : $verifier;
  }

  /**
   * shorten
   * @param  $text string to shorten
   * @param  $length maximum lenght
   */
  private static function shorten( string $text, int $length = 15 ): string
  {
    if( mb_strlen( $text ) <= $length )
      return $text;
    return mb_substr( $text, 0, $length - 1 ) . '…';
  }

  /**
   * Sends a POST request to the specified URL with the given payload.
   *
   * @param $url The endpoint URL to which the POST request will be sent.
   * @param $payload The data to be sent in the body of the POST request.
   * @param $authorization The authorization header value (e.g., Bearer token).
   * @return array The response from the server, decoded as an associative array.
   */
  private function sendPost( string $url, array $payload = [], string $authorization = "" ): array
  {
    $this->logger->debug( 'sendPost', ['url' => $url] );

    $ch = curl_init( $url );
    curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 5 );
    curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
    curl_setopt( $ch, CURLOPT_POST, true );
    curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query( $payload ) );
    curl_setopt( $ch, CURLOPT_HTTPHEADER, [
      'Content-Type: application/x-www-form-urlencoded',
      "Authorization: $authorization"
    ] );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
    curl_setopt( $ch, CURLOPT_FAILONERROR, false ); // To handle HTTP 4xx/5xx as response, not error
    curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, true ); // For security, disable only if needed

    $result = curl_exec( $ch );
    $error  = curl_error( $ch );
    $errno  = curl_errno( $ch );
    $httpCode = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
    unset( $ch );

    if( $result === false ) {
      throw new \RuntimeException( "sendPost: cURL error($errno) - $error" );
    }

    $decoded = json_decode( $result, true );
    $isJson  = json_last_error() === JSON_ERROR_NONE;

    if( $httpCode >= 400 ) {
      if( $isJson && isset( $decoded['error'] ) ) {
        $this->logger->critical( 'sendPost: Azure AD error response', $decoded );
        throw new AzureOAuthException(
          sprintf( '%s: %s', $decoded['error'], $decoded['error_description'] ?? 'no description provided' ),
          $decoded
        );
      }
      throw new \RuntimeException( 'sendPost: Bad HTTP response - ' . $httpCode );
    }

    if( !$isJson ) {
      $this->logger->alert( 'sendPost response not JSON', [
        'url'      => $url,
        'response' => $result
      ] );
      throw new \RuntimeException( 'sendPost: JSON decode error ' . json_last_error_msg() );
    }

    $this->logger->debug( 'sendPost: valid response' );
    return $decoded;
  }
  /**
   * Sends a GET request to the specified URL with the given payload and authorization header.
   *
   * @param string $url The endpoint URL to send the GET request to.
   * @param array $payload The query parameters to include in the request.
   * @param string $authorization The authorization header value (e.g., Bearer token).
   * @return array The response data as an associative array.
   */
  private function sendGet( string $url, array $payload = [], string $authorization = "" ): array
  {
    $this->logger->debug( 'sendGet', ['url' => $url] );

    $queryString = http_build_query( $payload );
    $fullUrl     = $url . '?' . $queryString;

    $ch = curl_init( $fullUrl );
    curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 5 );
    curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
    curl_setopt( $ch, CURLOPT_HTTPHEADER, [
      'Content-Type: application/x-www-form-urlencoded',
      "Authorization: $authorization"
    ] );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
    curl_setopt( $ch, CURLOPT_FAILONERROR, false ); // To handle HTTP errors manually
    curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, true );

    $result   = curl_exec( $ch );
    $error    = curl_error( $ch );
    $errno    = curl_errno( $ch );
    $httpCode = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
    unset( $ch );

    if( $result === false ) {
      throw new \RuntimeException( "sendGet: cURL error($errno) - $error" );
    }

    $decoded = json_decode( $result, true );
    $isJson  = json_last_error() === JSON_ERROR_NONE;

    if( $httpCode >= 400 ) {
      if( $isJson && isset( $decoded['error'] ) ) {
        $graphError = $decoded['error'];
        $this->logger->critical( 'sendGet: Graph error response', is_array( $graphError ) ? $graphError : ['error' => $graphError] );
        throw new AzureOAuthException(
          is_array( $graphError )
            ? sprintf( '%s: %s', $graphError['code'] ?? 'error', $graphError['message'] ?? 'no description provided' )
            : (string) $graphError,
          $decoded
        );
      }
      throw new \RuntimeException( 'sendGet: Bad HTTP response - ' . $httpCode );
    }

    if( !$isJson ) {
      $this->logger->alert( 'sendGet response not JSON', [
        'url'      => $url,
        'response' => $result
      ] );
      throw new \RuntimeException( 'sendGet response not JSON' );
    }

    $this->logger->debug( 'sendGet valid response' );
    return $decoded;
  }

}