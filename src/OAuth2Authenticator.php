<?php declare(strict_types=1);

namespace Kingsoft\OAuth2;

use Psr\Http\Message\ResponseInterface;
use Kingsoft\Http\StatusCode;
use Psr\Log\LoggerInterface;

abstract class OAuth2Authenticator
{
    protected readonly string $client_id;
    protected readonly string $client_secret;
    protected readonly string $redirect_url;
    protected readonly LoggerInterface $logger;

    private ?string $get_state_callback = null;
    private ?string $logon_callback = null;
    private ?string $check_state_callback = null;

    public function __construct(
        string $client_id,
        string $client_secret,
        string $redirect_url,
        ?LoggerInterface $logger = new \Psr\Log\NullLogger()
    ) {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->redirect_url = $redirect_url;
        $this->logger = $logger;
    }

    abstract protected function getAuthUrl(): string;
    abstract protected function getTokenUrl(): string;
    abstract protected function getUserInfoUrl(): string;
    abstract protected function getScope(): string;

    public function setGetStateCallback(string $callback): self
    {
        $this->get_state_callback = $callback;
        return $this;
    }

    public function setLogonCallback(string $callback): self
    {
        $this->logon_callback = $callback;
        return $this;
    }

    public function setCheckStateCallback(string $callback): self
    {
        $this->check_state_callback = $callback;
        return $this;
    }

    public function handleAuthorizationCode(): void
    {
        if (isset($_POST['error'])) {
            $this->handleError($_POST['error']);
        }

        if (!$this->isStateValid($_POST['state'] ?? '')) {
            throw new \RuntimeException('State mismatch detected.');
        }

        $accessToken = $this->getAccessToken($_POST['code'] ?? '');
        $userResource = $this->getUserResource($accessToken);

        if (!$this->processLogon($userResource)) {
            session_unset();
            throw new \RuntimeException('Logon error: user not recognized.');
        }

        $this->logger->debug('Redirect to /', ['user' => $userResource]);
        header('Location: /');
        exit();
    }

    private function handleError(string $error): void
    {
        $this->logger->critical('Received error', ['error' => $error]);
        http_response_code(StatusCode::BadGateway->value);
        exit();
    }

    private function isStateValid(string $state): bool
    {
        return is_callable($this->check_state_callback) && call_user_func($this->check_state_callback, $state);
    }

    private function processLogon(array $userResource): bool
    {
        $this->logger->info('User logged on', ['user' => $userResource]);
        if (is_callable($this->logon_callback)) {
            return call_user_func($this->logon_callback, $userResource);
        }
        return true;
    }

    public function requestAuthCode(): void
    {
        $state = $this->get_state_callback ? call_user_func($this->get_state_callback) : session_id();
        $params = [
            'client_id' => $this->client_id,
            'scope' => $this->getScope(),
            'redirect_uri' => $this->redirect_url,
            'response_type' => 'code',
            'state' => $state,
        ];
        $this->logger->debug('Redirecting to authorization URL', ['url' => $this->getAuthUrl(), 'state' => $state]);
        header('Location: ' . $this->getAuthUrl() . '?' . http_build_query($params));
        exit();
    }

    private function getAccessToken(string $authorization_code): string
    {
        $params = [
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret,
            'redirect_uri' => $this->redirect_url,
            'grant_type' => 'authorization_code',
            'code' => $authorization_code,
        ];
        return $this->sendPost($this->getTokenUrl(), $params)['access_token'] ?? throw new \RuntimeException('No access token');
    }

    private function getUserResource(string $access_token): array
    {
        return $this->sendGet($this->getUserInfoUrl(), [], "Bearer $access_token") ?? throw new \RuntimeException('No user resource');
    }

    private function sendPost(string $url, array $payload): array
    {
        $opts = [
            'http' => [
                'method' => 'POST',
                'header' => 'Content-Type: application/x-www-form-urlencoded',
                'content' => http_build_query($payload)
            ]
        ];
        return $this->fetchContent($url, $opts);
    }

    private function sendGet(string $url, array $payload, string $authorization): array
    {
        $opts = [
            'http' => [
                'method' => 'GET',
                'header' => ['Authorization: ' . $authorization]
            ]
        ];
        return $this->fetchContent($url . '?' . http_build_query($payload), $opts);
    }

    private function fetchContent(string $url, array $opts): array
    {
        $context = stream_context_create($opts);
        if (false === $result = @file_get_contents($url, false, $context)) {
            http_response_code(StatusCode::BadGateway->value);
            $this->logger->warning('fetchContent: file_get_content failed', ['url' => $url]);
            throw new \RuntimeException('fetchContent: file_get_content failed');
        }
        return json_decode($result, true) ?: throw new \RuntimeException('Invalid JSON response');
    }
}

