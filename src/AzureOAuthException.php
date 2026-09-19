<?php declare(strict_types=1);
namespace Kingsoft\Azure;

/**
 * Thrown when Azure AD or Graph returns a structured error response
 * (e.g. `{"error": "...", "error_description": "...", "error_codes": [...]}`
 * from the token endpoint, or `{"error": {"code": "...", "message": "..."}}`
 * from Graph). Carries the full decoded body via getError() so callers can
 * inspect fields beyond the exception message -- notably `error_description`
 * and the AADSTS `error_codes`, which are otherwise only visible in the log.
 */
class AzureOAuthException extends \RuntimeException
{
  public function __construct(
    string $message,
    private readonly array $error = [],
    int $code = 0,
    ?\Throwable $previous = null
  ) {
    parent::__construct( $message, $code, $previous );
  }

  public function getError(): array
  {
    return $this->error;
  }
}
