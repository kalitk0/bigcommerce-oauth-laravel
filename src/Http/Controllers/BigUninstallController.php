<?php

namespace CronixWeb\BigCommerceAuth\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use CronixWeb\BigCommerceAuth\Facades\BigCommerceAuth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Response;

class BigUninstallController extends Controller
{
    public function uninstall(Request $request)
    {
        $this->validatePerms($request);

        $validatedSignedPayload = $this->verifySignedPayload($request);




        if ($validatedSignedPayload) {
            $store = $this->getStoreModelClass()::query()
                ->where('bc_store_hash', $validatedSignedPayload['store_hash'])->with('user')
                ->first();
            if (!$store) {
                return false;
            }
            else{
                $store->bc_store_hash = null;
                $store->bc_access_token = null;
                $store->provider = 'local';
                $store->save();
            }


            \App\Jobs\BigCommerce\AppUninstalledJob::dispatch($store);
        }
    }

    protected function removeStoreData($signedPayload)
    {
        $uninstallCallback = BigCommerceAuth::getUninstallStoreCallBack();

        if ($signedPayload && $uninstallCallback) {
            $uninstallCallback($signedPayload);
        }
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
    
    protected function getStoreModelClass(): string
    {
        return Config::get('bigcommerce-auth.models.store_model');
    }

    /**
     * Verify Signed Payload
     * @param Request $request
     * @return bool|array
     */
    protected function verifySignedPayload(Request $request): bool|array
    {
        return BigCommerceAuth::verifySignedPayload($request->get('signed_payload'));
    }
}
