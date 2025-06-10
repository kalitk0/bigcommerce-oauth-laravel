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
use App\Models\Shop\ShopSetting;
use Bigcommerce\Api\Client as Bigcommerce;

class BigInstallController extends Controller
{
    public function install(Request $request): \Illuminate\Http\Response|RedirectResponse
    {
        logger(json_encode($request));
        $this->validatePerms($request);
		
        $redirect_path = Config::get('bigcommerce-auth.redirect_path', '/');
        $r = $this->saveInformation($request);
        if ($r) {
        	logger(1);
            logger(json_encode($r));
            logger(2);
            logger(BigCommerceAuth::getStoreHash());
            if(Auth::user()) {
                $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
                $payload = json_encode(['hash' => $r->bc_store_hash]);
                $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
                $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
                $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, 'abC123!', true);
                $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
                $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
                \App\Jobs\BigCommerce\AfterAuthenticateJob::dispatch($r);

                return Response::redirectTo($redirect_path . "?signed_payload=" . $jwt);
            }
            else{
            	\App\Jobs\BigCommerce\AfterAuthenticateJob::dispatch($r);
                return Response::redirectTo($redirect_path);
            }
        }
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
    protected function saveInformation(Request $request)
    {
       
        $response = BigCommerceAuth::install(
            $request->get('code'),
            $request->get('scope'),
            $request->get('context')
        );

        if ($response) {
          //  $user = $this->saveUserIfNotExist($response['user']['email']);
            $store = $this->saveStoreIfNotExist($response['context'], $response['access_token']);
            if (isset($store->id)) {
                if (isset($store->user) && $store->user) {
                    Auth::login($store->user);
                }
                else{
                    $store->user = null;
                }
                BigCommerceAuth::setStoreHash($store->bc_store_hash);
                BigCommerceAuth::callInstallCallback($store->user, $store);
                BigCommerceAuth::callLoadCallback($store->user, $store);
                return $store;

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
            ->where('bc_store_hash', $hash)->with('user')
            ->first();
        if ($store) {
            $store->bc_access_token = $access_token;
            Bigcommerce::configure([
            'client_id' => getenv('BC_CLIENT_ID'),
            'auth_token' => $access_token,
            'store_hash' => $hash,
        ]);
            $bcstore = Bigcommerce::getStore();
            $store->provider = 'bc';
            $store->needs_update = 0;
            $store->ready = 1;
            $store->domain = $bcstore->domain;
            $store->name = $bcstore->name;
            
            $store->currency = $bcstore->currency;
            $store->url = $bcstore->secure_url;
            $store->shop_owner = $bcstore->first_name.''. $bcstore->last_name;
            $store->timezone = $bcstore->timezone->name;
            $store->shop_email = $bcstore->admin_email;
            $store->customer_email = $bcstore->admin_email;
            $store->country_code = $bcstore->country_code;
            $store->country_name = $bcstore->country;
            $store->save();
            return $store;
        }
        
        Bigcommerce::configure([
            'client_id' => getenv('BC_CLIENT_ID'),
            'auth_token' => $access_token,
            'store_hash' => $hash,
        ]);
        $bcstore = Bigcommerce::getStore();
        logger(json_encode($bcstore));
        logger(json_encode(Bigcommerce::getLastError()));

        $store =  $this->getStoreModelClass()::query()->create([
            'bc_store_hash' => $hash,
            'bc_access_token' => $access_token,
            'provider' => 'bc',
            'needs_update' => 0,
            'ready' => 1,
            'domain' => $bcstore->domain,
            'name' => $bcstore->name,
            'friendly_name' => $bcstore->name,
            'currency' => $bcstore->currency,
            'url' => $bcstore->secure_url,
            'shop_owner' => $bcstore->first_name.''. $bcstore->last_name,
            'timezone' => $bcstore->timezone->name,
            'shop_email' => $bcstore->admin_email,
            'customer_email' => $bcstore->admin_email,
            'country_code' => $bcstore->country_code,
            'country_name' => $bcstore->country
        ]);
        
        
        
        $shopsettings = new ShopSetting;
        $shopsettings->shop_id = $store->id;
        $shopsettings->auto_fulfillment = 1;
        $shopsettings->order_failed_payment_notification = 1;
        $shopsettings->order_status_change_notification = 1;
        $shopsettings->order_problem_notification = 1;
        $shopsettings->product_availability_change_notification = 1;
        $shopsettings->save();
        return $store;
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
