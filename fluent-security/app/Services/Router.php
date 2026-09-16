<?php

namespace FluentAuth\App\Services;

class Router
{
    private $namespace = '';

    public function __construct($namespace)
    {
        $this->namespace = $namespace;
    }

    public function route($method, $endpoint, $callback, $permissions = [])
    {
        /*
         * `{id}` stays numeric, so a route declared with one still refuses anything that is
         * not a number before the controller is reached.
         */
        $endpoint = str_replace('{id}', '(?P<id>[\d]+)', $endpoint);

        /*
         * Any other `{name}` is a slug - the name of a setting, a check, a provider. Without
         * this they were left in the path verbatim and the route simply never matched, which
         * shows up as a 404 on an endpoint that looks correctly registered.
         */
        $endpoint = preg_replace('/\{([a-z_]+)\}/', '(?P<$1>[a-zA-Z0-9_\-]+)', $endpoint);

        register_rest_route($this->namespace, $endpoint, array(
            'methods'  => $method,
            'callback' => function($request) use ($callback) {
                $result = call_user_func($callback, $request);
                if(is_wp_error($result)) {
                    return $result;
                }
                return rest_ensure_response( $result );
            },
            'permission_callback' => function($request) use ($permissions) {
                if(is_callable($permissions)) {
                    return call_user_func($permissions, $request);
                }

                if(is_array($permissions) && count($permissions)) {
                    foreach ($permissions as $permission) {
                        if(current_user_can($permission)) {
                            return true;
                        }
                    }
                }

                return false;
            }
        ));

        return $this;
    }

    public function get($endpoint, $callback, $permissions = [])
    {
        $this->route(\WP_REST_Server::READABLE, $endpoint, $callback, $permissions);
        return $this;
    }

    public function post($endpoint, $callback, $permissions = [])
    {
        $this->route(\WP_REST_Server::CREATABLE, $endpoint, $callback, $permissions);
        return $this;
    }
}
