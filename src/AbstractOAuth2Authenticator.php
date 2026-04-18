<?php declare(strict_types=1);
namespace Kingsoft\OAuth2;

use Kingsoft\Http\StatusCode;

/**
 * Abstract base class for OAuth2 authentication providers.
 * Handles the common authorization-code flow, state validation,
 * session management, and HTTP transport.
 * Subclasses implement provider-specific token exchange, user-info
 * retrieval, and logon processing.
 */
abstract class AbstractOAuth2Authenticator
{
  public function __construct(
    readonly string $client_id,
    readonly string $client_secret,
    readonly string $redirect_url,
    readonly \Psr\Log\LoggerInterface $logger = new \Psr\Log\NullLogger()
  ) {
    $this->logger->debug( \get_class( $this ) . ' loaded' );
  }

  // #MARK: Callbacks
  protected ?string $get_state_callback = null;
  public function setGetStateCallback( string $callback ): self
  {
    $this->get_state_callback = $callback;
    return $this;
  }

  protected ?string $logon_callback = null;
  public function setLogonCallback( string $callback ): self
  {
    $this->logon_callback = $callback;
    return $this;
  }

  protected ?string $check_state_callback = null;
  public function setCheckStateCallback( string $callback ): self
  {
    $this->check_state_callback = $callback;
    return $this;
  }

  // #MARK: Abstract provider-specific methods
  abstract protected function getAccessToken( string $authorization_code ): string;
  abstract protected function getUserResource( string $access_token ): array;
  abstract protected function processLogon( array $userResource ): bool;
  abstract protected function getSuccessLogContext( array $userResource ): array;

  // #MARK: Authorization code flow
  /**
   * Handle the OAuth2 authorization-code callback (POST from the provider).
   * Validates state, exchanges the code for a token, fetches the user
   * resource, and invokes the logon callback.
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

    $accessToken  = $this->getAccessToken( $_POST['code'] ?? '' );
    $userResource = $this->getUserResource( $accessToken );

    if( !$this->processLogon( $userResource ) ) {
      session_destroy();
      throw new \RuntimeException( 'Logon error: user not recognized.' );
    }

    $this->logger->debug( 'Redirect to /', $this->getSuccessLogContext( $userResource ) );

    header( 'Location: /' );
    exit();
  }

  // #MARK: Helpers
  protected function getState(): string
  {
    return $this->get_state_callback ? \call_user_func( $this->get_state_callback ) : session_id();
  }

  private function handleError( string $error ): never
  {
    $this->logger->alert( 'Received error', ['error' => $error] );
    http_response_code( StatusCode::BadGateway->value );
    exit();
  }

  private function isStateValid( string $state ): bool
  {
    return is_callable( $this->check_state_callback ) && \call_user_func( $this->check_state_callback, $state );
  }

  protected static function shorten( string $text, int $length = 15 ): string
  {
    if( mb_strlen( $text ) <= $length )
      return $text;
    return mb_substr( $text, 0, $length - 1 ) . '…';
  }

  // #MARK: HTTP transport
  protected function sendPost( string $url, array $payload = [], string $authorization = "" ): array
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
    curl_setopt( $ch, CURLOPT_FAILONERROR, false );
    curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, true );
    curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 2 );

    $result   = curl_exec( $ch );
    $error    = curl_error( $ch );
    $errno    = curl_errno( $ch );
    $httpCode = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
    unset( $ch );

    if( $result === false ) {
      throw new \RuntimeException( "sendPost: cURL error($errno) - $error" );
    }

    if( $httpCode >= 400 ) {
      throw new \RuntimeException( 'sendPost: Bad HTTP response - ' . $httpCode );
    }

    $decoded = json_decode( $result, true );
    if( json_last_error() !== JSON_ERROR_NONE ) {
      $this->logger->alert( 'sendPost response not JSON', ['url' => $url] );
      throw new \RuntimeException( 'sendPost: JSON decode error ' . json_last_error_msg() );
    }

    return $decoded;
  }

  protected function sendGet( string $url, array $payload = [], string $authorization = "" ): array
  {
    $this->logger->debug( 'sendGet', ['url' => $url] );

    $fullUrl = $url . '?' . http_build_query( $payload );
    $ch      = curl_init( $fullUrl );
    curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 5 );
    curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
    curl_setopt( $ch, CURLOPT_HTTPHEADER, [
      "Authorization: $authorization"
    ] );
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
    curl_setopt( $ch, CURLOPT_FAILONERROR, false );
    curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, true );
    curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 2 );

    $result   = curl_exec( $ch );
    $error    = curl_error( $ch );
    $errno    = curl_errno( $ch );
    $httpCode = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
    unset( $ch );

    if( $result === false ) {
      throw new \RuntimeException( "sendGet: cURL error($errno) - $error" );
    }

    if( $httpCode >= 400 ) {
      throw new \RuntimeException( 'sendGet: Bad HTTP response - ' . $httpCode );
    }

    $decoded = json_decode( $result, true );
    if( json_last_error() !== JSON_ERROR_NONE ) {
      $this->logger->alert( 'sendGet response not JSON', ['url' => $url] );
      throw new \RuntimeException( 'sendGet: JSON decode error ' . json_last_error_msg() );
    }

    return $decoded;
  }
}
