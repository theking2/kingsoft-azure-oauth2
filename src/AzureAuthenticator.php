<?php declare(strict_types=1);
namespace Kingsoft\Azure;

use Psr\Http\Message\ResponseInterface;
use Kingsoft\Http\StatusCode;
use Psr\Log\LoggerInterface;
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
    readonly LoggerInterface $logger = new \Psr\Log\NullLogger()
  ) {
  }
  private string $tenant_id = '';
  public function setTenantId( string $tenant_id ): self
  {
    $this->tenant_id = $tenant_id;
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
    if( isset( $_POST['error'] ) ) {
      $this->handleError( $_POST['error'] );
    }

    if( !$this->isStateValid( $_POST['state'] ?? '' ) ) {
      throw new \RuntimeException( 'State mismatch detected.' );
    }

    $accessToken  = $this->getAccessToken( $_POST['code'] ?? '' );
    $userResource = $this->getUserResource( $accessToken );

    if( !$this->processLogon( $userResource ) ) {
      session_unset();
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
    $this->logger->critical( 'Received error', ['error' => $error] );
    http_response_code( StatusCode::BadGateway->value );
    exit();
  }
  private function isStateValid( string $state ): bool
  {
    return is_callable( $this->check_state_callback ) && call_user_func( $this->check_state_callback, $state );
  }

  private function processLogon( array $userResource ): bool
  {
    $this->logger->info( 'AD User logged on', [
      'userPrincipalName' => $userResource['userPrincipalName'],
      'displayName'       => $userResource["displayName"]
    ] );

    if( is_callable( $this->logon_callback ) ) {
      if( !call_user_func( $this->logon_callback, $userResource ) ) {
        $this->logger->alert( 'Logon error', [
          'userPrincipalName' => $userResource['userPrincipalName'],
          'displayName'       => $userResource["displayName"],
          'id'                => $userResource['id']
        ] );
        http_response_code( StatusCode::Forbidden->value );
        exit();
      }
    }

    return true;
  }

  /**
   * MARK: Handle a POST from Azure AD
   * Redirects to Azure AD for authorization
   */
  public function requestAzureAdCode(): void
  {
    $state  = $this->get_state_callback ? call_user_func( $this->get_state_callback ) : session_id();
    $params = [
      'client_id'     => $this->client_id,
      'scope'         => AzureAuthenticator::MSGRAPH_SCOPE,
      'redirect_uri'  => $this->redirect_url,
      'response_mode' => 'form_post',
      'response_type' => 'code',
      'state'         => $state,
    ];
    $this->logger->debug( 'Redirect to Azure AD authorizer', ['url' => $this->redirect_url, 'state' => self::shorten( $state )] );
    $login_url = $this->getAuthUrl();
    header( 'Location: ' . $login_url . '?' . http_build_query( $params ) );
    // we hear back in handleAuthorizationCode
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
      ??throw new \RuntimeException( 'No user resource' );
  }
  /**
   * getAccessToken
   * Only accept bearer type tokens
   * @param $authorization_code received from AD to access graph
   * @throws \RuntimeException if the response is not JSON
   */
  private function getAccessToken( string $authorization_code ): string
  {
    $this->logger->debug( 'Getting access token', ['authorization_code' => self::shorten( $authorization_code, 15 )] );

    /* Request token from Azure AD tokenizer */
    $token_url = $this->getTokenUrl();

    $params = [
      'client_id'     => $this->client_id,
      'client_secret' => $this->client_secret,
      'scope'         => AzureAuthenticator::MSGRAPH_SCOPE,
      'redirect_uri'  => $this->redirect_url,
      'response_mode' => 'form_post',
      'grant_type'    => 'authorization_code',
      'response_type' => 'code id_token offline_access',
      'code'          => $authorization_code,
    ];

    if( $answer = $this->sendPost( $token_url, $params ) ) {
      if( isset( $answer['error'] ) ) {
        $this->logger->critical( 'sendPost error response', ['error' => $answer['error']] );
        http_response_code( StatusCode::BadGateway->value );
        throw new \RuntimeException( 'sendPost error response' );
      }
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
      return $answer['access_token']
        ??throw new \RuntimeException( 'No access token' );
    } else {
      $this->logger->critical( 'No answer from sendPost' );
      http_response_code( StatusCode::BadGateway->value );
      throw new \RuntimeException( 'No answer from sendPost' );
    }
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

  private function sendPost( string $url, array $payload ): array
  {
    $opts    = [
      'http' => [
        'method'  => 'POST',
        'header'  => 'Content-Type: application/x-www-form-urlencoded',
        'content' => http_build_query( $payload )
      ]
    ];
    $context = stream_context_create( $opts );
    // we don-t want warnings, hence the @
    // but monolog error handler will report this anyway
    if( false === $result = @file_get_contents( $url, false, $context ) ) {
      http_response_code( StatusCode::BadGateway->value );
      $this->logger->warning( 'sendPost: file_get_content false', ['url' => $url, 'payload' => $payload] );
      throw new \RuntimeException( 'sendPost: file_get_content false' );
    }

    $result = json_decode( $result, true );
    if( json_last_error() !== JSON_ERROR_NONE ) {
      $this->logger->warning( 'JSON decode error: ' . json_last_error_msg(), ['result' => $result] );
      http_response_code( StatusCode::BadGateway->value );
      exit( 0 );
    }
    $this->logger->debug( 'valid sendPost response' );
    return $result;
  }

  private function sendGet( string $url, array $payload, string $authorization ): array
  {
    $opts = [
      'http' => [
        'method' => 'GET',
        'header' => [
          'Content-Type: application/x-www-form-urlencoded',
          "Authorization: $authorization"
        ]
      ]
    ];

    $context = stream_context_create( $opts );
    // we don-t want warnings, hence the @
    if( false !== $result = @file_get_contents( $url . '?' . http_build_query( $payload ), false, $context ) ) {

      if( $result = json_decode( $result, true ) ) {
        $this->logger->debug( 'sendGet response', $result );
        return $result;

      } else {
        $this->logger->alert( 'sendGet response not JSON', ['url' => $url, 'payload' => $payload, 'response' => $result] );
        throw new \RuntimeException( 'sendGet response not JSON' );
      }
    } else {
      session_destroy();
      http_response_code( StatusCode::BadGateway->value );
      $this->logger->warning( 'sendGet: file_get_content false', ['url' => $url, 'payload' => $payload] );
      exit;
    }
  }

}
