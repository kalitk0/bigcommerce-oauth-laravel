<?php

namespace CronixWeb\BigCommerceAuth;

use Closure;
use Exception;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use CronixWeb\BigCommerceAuth\Models\Store;

class BigCommerceAuth
{
    private Closure $installCallback;

    private Closure $loadCallback;

    private ?Closure $getStoreAccessTokenCallback;

    private Closure $uninstallStoreCallBack;

    private Closure $removeStoreUserCallBack;

    private Closure $findStoreFromSessionCallBack;

    /**
     * @return string
     */
    private function getClientId(): string
    {
        return Config::get('bigcommerce-auth.client_id', '');
    }

    /**
     * @return string
     */
    private function getSecret(): string
    {
        return Config::get('bigcommerce-auth.secret', '');
    }

    /**
     * @throws Exception
     */
    private function getRedirectURL(): string
    {
        return route('bigcommerce-install');
    }

    /**
     * Get session key from config
     * @return string
     */
    private function getSessionKey(): string
    {
        return Config::get('bigcommerce-auth.session_key', 'bigcommerce_auth');
    }

    /**
     * Get store hash session key
     * @return string
     */
    private function getStoreHashSessionKey(): string
    {
        return $this->getSessionKey() . '.store_hash_' . sha1(static::class);
    }

    /**
     * @throws Exception
     */
    public function install(string $code, string $scope, string $context): array|false
    {
        if (App::isProduction()) {
            $response = Http::post('https://login.bigcommerce.com/oauth2/token', [
                'client_id' => $this->getClientId(),
                'client_secret' => $this->getSecret(),
                'context' => $context,
                'code' => $code,
                'grant_type' => 'authorization_code',
                'redirect_uri' => $this->getRedirectURL(),
                'scope' => $scope,
            ]);
        } else {
            $response = Http::withoutVerifying()->post('https://login.bigcommerce.com/oauth2/token', [
                'client_id' => $this->getClientId(),
                'client_secret' => $this->getSecret(),
                'context' => $context,
                'code' => $code,
                'grant_type' => 'authorization_code',
                'redirect_uri' => $this->getRedirectURL(),
                'scope' => $scope,
            ]);
        }

        if (!$response->ok() && !$response->successful()) return false;

        return json_decode($response->body(), true);
    }

    /**
     * @param string $signedRequest
     * @return array|false
     */
    public function verifySignedPayload(string $signedRequest): array|false
    {
        list($encodedData, $encodedSignature) = explode('.', $signedRequest, 2);

        // decode the data
        $signature = base64_decode($encodedSignature);
        $jsonStr = base64_decode($encodedData);
        $data = json_decode($jsonStr, true);

        // confirm the signature
        $expectedSignature = hash_hmac('sha256', $jsonStr, $this->getSecret());
        if (!hash_equals($expectedSignature, $signature)) {
            return false;
        }

        return $data;
    }

    /**
     * Get BigCommerce user requested store hash
     * @return string|false
     */
    public function getStoreHash(): string|false
    {
        return Session::get($this->getStoreHashSessionKey(), false);
    }

    /**
     * Save BigCommerce user requested store hash in session
     * @param string $store_hash
     */
    public function setStoreHash(string $store_hash): void
    {
        Session::put($this->getStoreHashSessionKey(), $store_hash);
    }

    /**
     * Get store access token out of the box
     * Note: you need to set store hash first
     * @return string|bool
     * @throws Exception
     */
    public function getStoreAccessToken(): string|bool
    {
        if (!($store_hash = $this->getStoreHash()))
            throw new Exception('Store hash is not set. Please set store hash using setStoreHash method.');

        if ($this->getGetStoreAccessTokenCallback() != null) {
            return ($this->getGetStoreAccessTokenCallback())($store_hash);
        }

        $store = Store::query()
            ->select(['id', 'bc_access_token'])
            ->where('bc_store_hash', $store_hash)
            ->first();
        if (!$store)
            return false;

        return (string)$store->access_token;
    }

    /**
     * Set install callback function that will execute after install done
     * @param Closure $installCallback
     */
    public function setInstallCallback(Closure $installCallback): void
    {
        $this->installCallback = $installCallback;
    }

    /**
     * Set callback function that will execute after load done
     * @param Closure $loadCallback
     */
    public function setLoadCallback(Closure $loadCallback): void
    {
        $this->loadCallback = $loadCallback;
    }

    /**
     * Execute install callback
     * @param $user
     * @param $store
     */
    public function callInstallCallback($user, $store)
    {
        if (isset($this->installCallback))
            ($this->installCallback)($user, $store);
    }

    /**
     * @param $user
     * @param $store
     * @return void
     */
    public function callLoadCallback($user, $store)
    {
        if (isset($this->loadCallback))
            ($this->loadCallback)($user, $store);
    }

    /**
     * @return Closure|null
     */
    public function getGetStoreAccessTokenCallback(): ?Closure
    {
        return $this->getStoreAccessTokenCallback;
    }

    /**
     * @param Closure $getStoreAccessTokenCallback
     */
    public function setGetStoreAccessTokenCallback(Closure $getStoreAccessTokenCallback): void
    {
        $this->getStoreAccessTokenCallback = $getStoreAccessTokenCallback;
    }

    /**
     * @return Closure|false
     */
    public function getUninstallStoreCallBack(): bool|Closure
    {
        return $this->uninstallStoreCallBack ?? false;
    }

    /**
     * @param Closure $uninstallStoreCallBack
     */
    public function setUninstallStoreCallBack(Closure $uninstallStoreCallBack): void
    {
        $this->uninstallStoreCallBack = $uninstallStoreCallBack;
    }

    /**
     * @return Closure|false
     */
    public function getRemoveStoreUserCallBack(): bool|Closure
    {
        return $this->removeStoreUserCallBack ?? false;
    }

    /**
     * @param Closure $removeStoreUserCallBack
     */
    public function setRemoveStoreUserCallBack(Closure $removeStoreUserCallBack): void
    {
        $this->removeStoreUserCallBack = $removeStoreUserCallBack;
    }

    /**
     * @return Closure|false
     */
    public function getFindStoreFromSessionCallBack(): bool|Closure
    {
        return $this->findStoreFromSessionCallBack ?? false;
    }

    /**
     * @param Closure $findStoreFromSessionCallBack
     */
    public function setFindStoreFromSessionCallBack(Closure $findStoreFromSessionCallBack): void
    {
        $this->findStoreFromSessionCallBack = $findStoreFromSessionCallBack;
    }

    /**
     * @return Model|Builder
     */
    protected function findStore(): Model|Builder
    {
        return (Config::get('bigcommerce-auth.models.store_model', Store::class))::query()
            ->where('bc_store_hash', $this->getStoreHash())
            ->firstOrFail();
    }

    /**
     * Get store object from session
     * @return Model|Builder
     */
    public function store():  Model|Builder
    {
        $findCallBack = $this->getFindStoreFromSessionCallBack();
        if ($findCallBack) {
            return $findCallBack();
        }

        return $this->findStore();
    }
}
