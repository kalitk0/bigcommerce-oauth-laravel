<?php

namespace CronixWeb\BigCommerceAuth\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Response;
use CronixWeb\BigCommerceAuth\Facades\BigCommerceAuth;
use Symfony\Component\HttpKernel\Exception\HttpException;

class BigInstallController extends Controller
{
    public function install(Request $request): \Illuminate\Http\Response|RedirectResponse
    {
        $this->validatePerms($request);

        $redirect_path = Config::get('bigcommerce-auth.redirect_path', '/');

        if ($this->saveInformation($request))
            return Response::redirectTo($redirect_path);

        $error_view = Config::get('bigcommerce-auth.error_view');

        if (!$error_view)
            $error_view = 'bigcommerce-auth::error';

        return Response::view($error_view, status: 500);
    }

    /**
     * Validate Parameters
     * @param Request $request
     * @return void
     */
    protected function validatePerms(Request $request)
    {
        $request->validate([
            'code' => 'required|string',
            'scope' => 'required|string',
            'context' => 'required|string',
        ]);
    }

    /**
     * Fetch and Save User and Store Information in database
     * @param Request $request
     * @return bool
     */
    protected function saveInformation(Request $request): bool
    {
        $response = BigCommerceAuth::install(
            $request->get('code'),
            $request->get('scope'),
            $request->get('context')
        );

        if ($response) {
            $user = $this->saveUserIfNotExist($response['user']['email']);
            $store = $this->saveStoreIfNotExist($response['context'], $response['access_token']);
            if (isset($user->id) && isset($store->id)) {
                if ($this->assignUserToStore($user->id, $store->id)) {
                    Auth::login($user);
                    BigCommerceAuth::setStoreHash($store->bc_store_hash);
                    BigCommerceAuth::callInstallCallback($user, $store);
                    BigCommerceAuth::callLoadCallback($user, $store);
                    return true;
                }
            }
        }

        return false;
    }

    protected function assignUserToStore($user_id, $store_id): bool
    {
        $store_has_users = Config::get('bigcommerce-auth.tables.store_has_users');
        if (DB::table($store_has_users)
            ->where('shop_id', $store_id)
            ->where('user_id', $user_id)
            ->exists())
            return true;

        return DB::table($store_has_users)->insert([
            'shop_id' => $store_id,
            'user_id' => $user_id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    protected function saveStoreIfNotExist(string $context, string $access_token): Model|Builder
    {
        $hash = explode('/', $context);
        $hash = $hash[1] ?? false;
        if (!$hash) {
            throw new HttpException(500, 'Store hash does not found in context!');
        }
        $store = $this->getStoreModelClass()::query()
            ->where('bc_store_hash', $hash)
            ->first();
        if ($store) {
            $store->bc_access_token = $access_token;
            $store->save();
            return $store; 
        }
        return $this->getStoreModelClass()::query()->create([
            'bc_store_hash' => $hash,
            'bc_access_token' => $access_token,
        ]);
    }

    /**
     * @param $email
     * @return Model|Builder|Authenticatable
     */
    protected function saveUserIfNotExist($email)
    {
        return $this->getUserModelClass()::query()->firstOrCreate([
            'email' => $email
        ]);
    }

    protected function getUserModelClass(): string
    {
        return Config::get('auth.providers.users.model');
    }

    protected function getStoreModelClass(): string
    {
        return Config::get('bigcommerce-auth.models.store_model');
    }
}
