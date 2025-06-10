<?php

namespace CronixWeb\BigCommerceAuth\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Response;
use CronixWeb\BigCommerceAuth\Facades\BigCommerceAuth;
use CronixWeb\BigCommerceAuth\Models\Store;

class BigLoadController extends Controller
{
    public function load(Request $request)
    {
        $this->validatePerms($request);

        $redirect_path = Config::get('bigcommerce-auth.redirect_path', '/');

        if ($this->verifyAndLoginUserIfNot($request))
            return Response::redirectTo($redirect_path."?signed_payload=".$request->get('signed_payload'));

        App::abort(403);
    }

    /**
     * Validate Parameters
     * @param Request $request
     * @return void
     */
    protected function validatePerms(Request $request)
    {
        $request->validate([
            'signed_payload' => 'required|string'
        ]);
    }

    protected function verifyAndLoginUserIfNot(Request $request): bool
    {
        $signed_payload = BigCommerceAuth::verifySignedPayload($request->get('signed_payload'));
        if ($signed_payload) {
            $store = $this->getStoreModelClass()::query()
                ->where('bc_store_hash', $signed_payload['store_hash'])->with('user')
                ->first();
            if (!$store) {
                return false;
            }
            else{
                if($store->user){
                    Auth::login($store->user);
                    BigCommerceAuth::setStoreHash($signed_payload['store_hash']);
                    BigCommerceAuth::callLoadCallback($store->user, $store);
                    return true;
                }
                else{
                    return false;
                }
            }
        }
        return false;
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
