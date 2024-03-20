<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean ifs <ifs148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace ifs\JWTAuth\Providers;

use Illuminate\Support\ServiceProvider;
use Namshi\JOSE\JWS;
use ifs\JWTAuth\Blacklist;
use ifs\JWTAuth\Claims\Factory as ClaimFactory;
use ifs\JWTAuth\Console\JWTGenerateSecretCommand;
use ifs\JWTAuth\Contracts\Providers\Auth;
use ifs\JWTAuth\Contracts\Providers\JWT as JWTContract;
use ifs\JWTAuth\Contracts\Providers\Storage;
use ifs\JWTAuth\Factory;
use ifs\JWTAuth\Http\Middleware\Authenticate;
use ifs\JWTAuth\Http\Middleware\AuthenticateAndRenew;
use ifs\JWTAuth\Http\Middleware\Check;
use ifs\JWTAuth\Http\Middleware\RefreshToken;
use ifs\JWTAuth\Http\Parser\AuthHeaders;
use ifs\JWTAuth\Http\Parser\InputSource;
use ifs\JWTAuth\Http\Parser\Parser;
use ifs\JWTAuth\Http\Parser\QueryString;
use ifs\JWTAuth\JWT;
use ifs\JWTAuth\JWTAuth;
use ifs\JWTAuth\JWTGuard;
use ifs\JWTAuth\Manager;
use ifs\JWTAuth\Providers\JWT\Lcobucci;
use ifs\JWTAuth\Providers\JWT\Namshi;
use ifs\JWTAuth\Validators\PayloadValidator;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * The middleware aliases.
     *
     * @var array
     */
    protected $middlewareAliases = [
        'jwt.auth' => Authenticate::class,
        'jwt.check' => Check::class,
        'jwt.refresh' => RefreshToken::class,
        'jwt.renew' => AuthenticateAndRenew::class,
    ];

    /**
     * Boot the service provider.
     *
     * @return void
     */
    abstract public function boot();

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerAliases();

        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerManager();
        $this->registerTokenParser();

        $this->registerJWT();
        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerClaimFactory();
        $this->registerPayloadFactory();
        $this->registerJWTCommand();

        $this->commands('ifs.jwt.secret');
    }

    /**
     * Extend Laravel's Auth.
     *
     * @return void
     */
    protected function extendAuthGuard()
    {
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $guard = new JWTGuard(
                $app['ifs.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    /**
     * Bind some aliases.
     *
     * @return void
     */
    protected function registerAliases()
    {
        $this->app->alias('ifs.jwt', JWT::class);
        $this->app->alias('ifs.jwt.auth', JWTAuth::class);
        $this->app->alias('ifs.jwt.provider.jwt', JWTContract::class);
        $this->app->alias('ifs.jwt.provider.jwt.namshi', Namshi::class);
        $this->app->alias('ifs.jwt.provider.jwt.lcobucci', Lcobucci::class);
        $this->app->alias('ifs.jwt.provider.auth', Auth::class);
        $this->app->alias('ifs.jwt.provider.storage', Storage::class);
        $this->app->alias('ifs.jwt.manager', Manager::class);
        $this->app->alias('ifs.jwt.blacklist', Blacklist::class);
        $this->app->alias('ifs.jwt.payload.factory', Factory::class);
        $this->app->alias('ifs.jwt.validators.payload', PayloadValidator::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     *
     * @return void
     */
    protected function registerJWTProvider()
    {
        $this->registerNamshiProvider();
        $this->registerLcobucciProvider();

        $this->app->singleton('ifs.jwt.provider.jwt', function ($app) {
            return $this->getConfigInstance('providers.jwt');
        });
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     *
     * @return void
     */
    protected function registerNamshiProvider()
    {
        $this->app->singleton('ifs.jwt.provider.jwt.namshi', function ($app) {
            return new Namshi(
                new JWS(['typ' => 'JWT', 'alg' => $this->config('algo')]),
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     *
     * @return void
     */
    protected function registerLcobucciProvider()
    {
        $this->app->singleton('ifs.jwt.provider.jwt.lcobucci', function ($app) {
            return new Lcobucci(
                $this->config('secret'),
                $this->config('algo'),
                $this->config('keys')
            );
        });
    }

    /**
     * Register the bindings for the Auth provider.
     *
     * @return void
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('ifs.jwt.provider.auth', function () {
            return $this->getConfigInstance('providers.auth');
        });
    }

    /**
     * Register the bindings for the Storage provider.
     *
     * @return void
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('ifs.jwt.provider.storage', function () {
            return $this->getConfigInstance('providers.storage');
        });
    }

    /**
     * Register the bindings for the JWT Manager.
     *
     * @return void
     */
    protected function registerManager()
    {
        $this->app->singleton('ifs.jwt.manager', function ($app) {
            $instance = new Manager(
                $app['ifs.jwt.provider.jwt'],
                $app['ifs.jwt.blacklist'],
                $app['ifs.jwt.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $this->config('blacklist_enabled'))
                            ->setPersistentClaims($this->config('persistent_claims'));
        });
    }

    /**
     * Register the bindings for the Token Parser.
     *
     * @return void
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('ifs.jwt.parser', function ($app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders,
                    new QueryString,
                    new InputSource,
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    /**
     * Register the bindings for the main JWT class.
     *
     * @return void
     */
    protected function registerJWT()
    {
        $this->app->singleton('ifs.jwt', function ($app) {
            return (new JWT(
                $app['ifs.jwt.manager'],
                $app['ifs.jwt.parser']
            ))->lockSubject($this->config('lock_subject'));
        });
    }

    /**
     * Register the bindings for the main JWTAuth class.
     *
     * @return void
     */
    protected function registerJWTAuth()
    {
        $this->app->singleton('ifs.jwt.auth', function ($app) {
            return (new JWTAuth(
                $app['ifs.jwt.manager'],
                $app['ifs.jwt.provider.auth'],
                $app['ifs.jwt.parser']
            ))->lockSubject($this->config('lock_subject'));
        });
    }

    /**
     * Register the bindings for the Blacklist.
     *
     * @return void
     */
    protected function registerJWTBlacklist()
    {
        $this->app->singleton('ifs.jwt.blacklist', function ($app) {
            $instance = new Blacklist($app['ifs.jwt.provider.storage']);

            return $instance->setGracePeriod($this->config('blacklist_grace_period'))
                            ->setRefreshTTL($this->config('refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator.
     *
     * @return void
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('ifs.jwt.validators.payload', function () {
            return (new PayloadValidator)
                ->setRefreshTTL($this->config('refresh_ttl'))
                ->setRequiredClaims($this->config('required_claims'));
        });
    }

    /**
     * Register the bindings for the Claim Factory.
     *
     * @return void
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('ifs.jwt.claim.factory', function ($app) {
            $factory = new ClaimFactory($app['request']);
            $app->refresh('request', $factory, 'setRequest');

            return $factory->setTTL($this->config('ttl'))
                           ->setLeeway($this->config('leeway'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     *
     * @return void
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('ifs.jwt.payload.factory', function ($app) {
            return new Factory(
                $app['ifs.jwt.claim.factory'],
                $app['ifs.jwt.validators.payload']
            );
        });
    }

    /**
     * Register the Artisan command.
     *
     * @return void
     */
    protected function registerJWTCommand()
    {
        $this->app->singleton('ifs.jwt.secret', function () {
            return new JWTGenerateSecretCommand;
        });
    }

    /**
     * Helper to get the config values.
     *
     * @param  string  $key
     * @param  string  $default
     * @return mixed
     */
    protected function config($key, $default = null)
    {
        return config("jwt.$key", $default);
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @param  string  $key
     * @return mixed
     */
    protected function getConfigInstance($key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
