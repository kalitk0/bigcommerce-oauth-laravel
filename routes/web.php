<?php

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;

Route::group([
    'prefix' => 'bc/auth'
], function () {

    Route::get('install', [Config::get('bigcommerce-auth.controllers.install'), 'install'])
        ->name('bigcommerce-install');

    Route::get('load', [Config::get('bigcommerce-auth.controllers.load'), 'load'])
        ->name('bigcommerce-load');

    Route::get('uninstall', [Config::get('bigcommerce-auth.controllers.uninstall'), 'uninstall'])
        ->name('bigcommerce-uninstall');

    Route::get('remove_user', [Config::get('bigcommerce-auth.controllers.remove_user'), 'removeUser'])
        ->name('bigcommerce-remove-user');

});
