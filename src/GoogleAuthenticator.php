<?php declare(strict_types=1);
namespace Kingsoft\Google;

use Kingsoft\Http\StatusCode;
use Kingsoft\OAuth2\AbstractOAuth2Authenticator;

/**
 * OAuth2 authenticator for Google.
 * Requests the userinfo.email and userinfo.profile scopes,
 * then calls the logon callback with the user resource.
 */
class GoogleAuthenticator extends AbstractOAuth2Authenticator
{
  private const GOOGLE_AUTH_URL     = 'https://accounts.google.com/o/oauth2/auth';
  private const GOOGLE_TOKEN_URL    = 'https://oauth2.googleapis.com/token';
  private const GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';
  private const GOOGLE_SCOPE        = 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile';

  // #MARK: Request auth code
  /**
   * Redirect the browser to the Google authorization endpoint.
   */
  public function requestGoogleAuthCode(): never
  {
    $state  = $this->getState();
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

  // #MARK: Provider-specific implementation
  protected function getAccessToken( string $authorization_code ): string
  {
    $this->logger->debug( 'Getting access token', ['authorization_code' => self::shorten( $authorization_code )] );

    $params = [
      'client_id'     => $this->client_id,
      'client_secret' => $this->client_secret,
      'redirect_uri'  => $this->redirect_url,
      'grant_type'    => 'authorization_code',
      'code'          => $authorization_code,
    ];

    return $this->sendPost( self::GOOGLE_TOKEN_URL, $params )['access_token']
      ?? throw new \RuntimeException( 'No access token' );
  }

  protected function getUserResource( string $access_token ): array
  {
    $this->logger->debug( 'Getting user resource from Google', ['access token' => self::shorten( $access_token )] );
    return $this->sendGet( self::GOOGLE_USERINFO_URL, [], "Bearer $access_token" )
      ?? throw new \RuntimeException( 'No user resource' );
  }

  protected function processLogon( array $userResource ): bool
  {
    $this->logger->info( 'Google User logged on', [
      'email' => $userResource['email'],
      'name'  => $userResource['name']
    ] );

    if( !\call_user_func( $this->logon_callback, $userResource ) ) {
      $this->logger->alert( 'Logon error', [
        'email' => $userResource['email'],
        'id'    => $userResource['id']
      ] );
      http_response_code( StatusCode::Forbidden->value );
      exit();
    }

    return true;
  }

  protected function getSuccessLogContext( array $userResource ): array
  {
    return [
      'email' => $userResource['email'],
      'name'  => $userResource['name']
    ];
  }
}
