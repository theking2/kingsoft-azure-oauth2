<?php declare(strict_types=1);
namespace Kingsoft\Google;

use Kingsoft\Http\StatusCode;
use Psr\Log\LoggerInterface;

class GoogleAuthenticator
{
  private const GOOGLE_AUTH_URL     = 'https://accounts.google.com/o/oauth2/auth';
  private const GOOGLE_TOKEN_URL    = 'https://oauth2.googleapis.com/token';
  private const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';
  private const GOOGLE_SCOPE        = 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile';

  public function __construct(
    readonly string $client_id,
    readonly string $client_secret,
    readonly string $redirect_url,
    readonly ?LoggerInterface $logger = new \Psr\Log\NullLogger()
  ) {
  }

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
      session_unset();
      throw new \RuntimeException( 'Logon error: user not recognized.' );
    }

    $this->logger->debug( 'Redirect to /', [
      'email' => $userResource['email'],
      'name'  => $userResource['name']
    ] );

    header( 'Location: /' );
    exit();
  }

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
    $this->logger->info( 'Google User logged on', [
      'email' => $userResource['email'],
      'name'  => $userResource['name']
    ] );

    if( !call_user_func( $this->logon_callback, $userResource ) ) {
      $this->logger->alert( 'Logon error', [
        'email' => $userResource['email'],
        'id'    => $userResource['id']
      ] );
      http_response_code( StatusCode::Forbidden->value );
      exit();
    }
    return true;
  }

  public function requestGoogleAuthCode(): void
  {
    $state  = $this->get_state_callback ? call_user_func( $this->get_state_callback ) : session_id();
    $params = [
      'client_id'     => $this->client_id,
      'scope'         => self::GOOGLE_SCOPE,
      'redirect_uri'  => $this->redirect_url,
      'response_type' => 'code',
      'state'         => $state,
    ];

    $this->logger->debug( 'Redirect to Google authorizer', ['url' => self::GOOGLE_AUTH_URL, 'state' => self::shorten( $state )] );
    header( 'Location: ' . self::GOOGLE_AUTH_URL . '?' . http_build_query( $params ) );
    exit();
  }

  private function getAccessToken( string $authorization_code ): string
  {
    $this->logger->debug( 'Getting access token', ['authorization_code' => self::shorten( $authorization_code, 15 )] );

    $params = [
      'client_id'     => $this->client_id,
      'client_secret' => $this->client_secret,
      'redirect_uri'  => $this->redirect_url,
      'grant_type'    => 'authorization_code',
      'code'          => $authorization_code,
    ];

    return $this->sendPost( self::GOOGLE_TOKEN_URL, $params )['access_token'] ?? throw new \RuntimeException( 'No access token' );
  }

  private function getUserResource( string $access_token ): array
  {
    $this->logger->debug( 'Getting user resource from Google', ['access token' => self::shorten( $access_token, 15 )] );
    return $this->sendGet( self::GOOGLE_USERINFO_URL, [], "Bearer $access_token" ) ?? throw new \RuntimeException( 'No user resource' );
  }

  private static function shorten( string $text, int $length = 15 ): string
  {
    return mb_strlen( $text ) <= $length ? $text : mb_substr( $text, 0, $length - 1 ) . '…';
  }

  private function sendPost( string $url, array $payload ): array
  {
    $this->logger->debug( 'sendPost', ['url' => $url] );

    $ch = curl_init( $url );
    curl_setopt( $ch, CURLOPT_POST, true );
    curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 5 );
    curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
    curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query( $payload ) );
    curl_setopt( $ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded'] );
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

  private function sendGet( string $url, array $payload, string $authorization ): array
  {
    $this->logger->debug( 'sendGet', ['url' => $url] );

    $fullUrl = $url . '?' . http_build_query( $payload );
    $ch      = curl_init( $fullUrl );
    curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 5 );
    curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
    curl_setopt( $ch, CURLOPT_HTTPHEADER, ["Authorization: $authorization"] );
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
