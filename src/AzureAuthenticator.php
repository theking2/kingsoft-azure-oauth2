<?php declare(strict_types=1);
namespace Kingsoft\Azure;

use Kingsoft\Http\StatusCode;
use Kingsoft\OAuth2\AbstractOAuth2Authenticator;

/**
 * OAuth2 authenticator for Azure AD / Microsoft Graph.
 * The client_id needs access to Graph to look up user details
 * (specifically email and object-id).
 * After success the logon callback is called to implement post-logon actions.
 */
class AzureAuthenticator extends AbstractOAuth2Authenticator
{
  private const MSONLINE_URL  = 'https://login.microsoftonline.com/';
  private const MSGRAPH_SCOPE = 'https://graph.microsoft.com/User.Read';
  private const MSGRAPH_URL   = 'https://graph.microsoft.com/v1.0/me/';

  private string $tenant_id = '';
  public function setTenantId( string $tenant_id ): self
  {
    $this->tenant_id = $tenant_id;
    return $this;
  }

  // #MARK: Request auth code
  /**
   * Redirect the browser to the Azure AD authorization endpoint.
   */
  public function requestAzureAdCode(): never
  {
    $state  = $this->getState();
    $params = [
      'client_id'     => $this->client_id,
      'scope'         => self::MSGRAPH_SCOPE,
      'redirect_uri'  => $this->redirect_url,
      'response_mode' => 'form_post',
      'response_type' => 'code',
      'state'         => $state,
    ];
    $this->logger->debug( 'Redirect to Azure AD authorizer', ['url' => $this->redirect_url, 'state' => self::shorten( $state )] );
    header( 'Location: ' . $this->getAuthUrl() . '?' . http_build_query( $params ) );
    exit;
  }

  // #MARK: Logout
  /**
   * Redirect the user to the Microsoft logout endpoint and then to the given URL.
   *
   * **Security notice:** `$redirectUrl` must be a trusted, application-controlled
   * value (e.g. a hard-coded URL or one taken from your own configuration).
   * Never pass a value that originates from user input (`$_GET`, `$_POST`, …).
   *
   * @param string $redirectUrl Trusted URL to redirect to after logout.
   *                            Must not be derived from user-supplied input.
   */
  public function logoutAzure( string $redirectUrl ): never
  {
    $logout_url = self::MSONLINE_URL . $this->tenant_id . "/oauth2/v2.0/logout?post_logout_redirect_uri=$redirectUrl";
    header( "Location: $logout_url" );
    exit;
  }

  // #MARK: Dry run (testing only)
  public function dryRun(): void
  {
    $this->logger->debug( 'Dry run' );
    $state  = $this->getState();
    $valid  = $this->check_state_callback ? \call_user_func( $this->check_state_callback, $state ) : true;
    $this->logger->debug( 'State validity', ['state' => self::shorten( $state ), 'valid' => $valid] );
    $params = [
      'client_id'     => $this->client_id,
      'scope'         => self::MSGRAPH_SCOPE,
      'redirect_uri'  => $this->redirect_url,
      'response_mode' => 'form_post',
      'response_type' => 'code',
      'state'         => $state,
    ];
    $this->logger->debug( 'Params', $params );
  }

  // #MARK: Provider-specific implementation
  protected function getAccessToken( string $authorization_code ): string
  {
    $this->logger->debug( 'Getting access token', ['authorization_code' => self::shorten( $authorization_code )] );

    $params = [
      'client_id'     => $this->client_id,
      'client_secret' => $this->client_secret,
      'scope'         => self::MSGRAPH_SCOPE,
      'redirect_uri'  => $this->redirect_url,
      'response_mode' => 'form_post',
      'grant_type'    => 'authorization_code',
      'response_type' => 'code id_token offline_access',
      'code'          => $authorization_code,
    ];

    $answer = $this->sendPost( $this->getTokenUrl(), $params );

    if( isset( $answer['error'] ) ) {
      $this->logger->critical( 'Token error response', ['error' => $answer['error']] );
      http_response_code( StatusCode::BadGateway->value );
      throw new \RuntimeException( 'Token error response' );
    }

    if( $answer['token_type'] !== 'Bearer' ) {
      $this->logger->critical( 'Wrong token type', ['token_type' => $answer['token_type']] );
      http_response_code( StatusCode::BadGateway->value );
      throw new \RuntimeException( 'Wrong token type' );
    }

    $this->logger->debug( 'Got access token', [
      'scope'          => $answer['scope'],
      'token_type'     => $answer['token_type'],
      'expires_in'     => $answer['expires_in'],
      'ext_expires_in' => $answer['ext_expires_in']
    ] );

    return $answer['access_token'] ?? throw new \RuntimeException( 'No access token' );
  }

  protected function getUserResource( string $access_token ): array
  {
    $this->logger->debug( 'Getting user resource from Graph', ['access token' => self::shorten( $access_token )] );
    return $this->sendGet( self::MSGRAPH_URL, [], "Bearer $access_token" )
      ?? throw new \RuntimeException( 'No user resource' );
  }

  protected function processLogon( array $userResource ): bool
  {
    $this->logger->info( 'AD User logged on', [
      'userPrincipalName' => $userResource['userPrincipalName'],
      'displayName'       => $userResource['displayName']
    ] );

    if( !\call_user_func( $this->logon_callback, $userResource ) ) {
      $this->logger->alert( 'Logon error', [
        'userPrincipalName' => $userResource['userPrincipalName'],
        'displayName'       => $userResource['displayName'],
        'id'                => $userResource['id']
      ] );
      http_response_code( StatusCode::Forbidden->value );
      exit();
    }

    return true;
  }

  protected function getSuccessLogContext( array $userResource ): array
  {
    return [
      'userPrincipalName' => $userResource['userPrincipalName'],
      'displayName'       => $userResource['displayName']
    ];
  }

  // #MARK: URL helpers
  private function getTokenUrl(): string
  {
    return self::MSONLINE_URL . $this->tenant_id . "/oauth2/v2.0/token";
  }

  private function getAuthUrl(): string
  {
    return self::MSONLINE_URL . $this->tenant_id . "/oauth2/v2.0/authorize";
  }
}
