<?php

namespace CronixWeb\BigCommerceAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;

class Store extends Model
{
    protected $fillable = [
        'bc_store_hash',
        'bc_access_token',
    ];

    public function getTable()
    {
        return Config::get('bigcommerce-auth.tables.stores', parent::getTable());
    }
}
