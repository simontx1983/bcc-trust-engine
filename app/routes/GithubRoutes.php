<?php
/**
 * GitHub Routes Registration
 *
 * @package BCC_Trust_Engine
 * @subpackage Routes
 * @version 2.3.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/*
|--------------------------------------------------------------------------
| Register GitHub Routes
|--------------------------------------------------------------------------
*/

add_action('rest_api_init', 'bcc_trust_register_github_routes');

function bcc_trust_register_github_routes() {

    if (class_exists('\\BCCTrust\\Controllers\\GitHubController')) {

        \BCCTrust\Controllers\GitHubController::register_routes();

    } else {

        error_log('BCC Trust: GitHubController class not found when registering routes');

    }

}


/*
|--------------------------------------------------------------------------
| Register API Index
|--------------------------------------------------------------------------
*/

add_action('rest_api_init', 'bcc_trust_register_index');

function bcc_trust_register_index() {

    register_rest_route('bcc-trust/v1', '/', [

        'methods' => 'GET',

        'callback' => 'bcc_trust_api_index',

        'permission_callback' => '__return_true'

    ]);

}


/*
|--------------------------------------------------------------------------
| API Index Endpoint
|--------------------------------------------------------------------------
*/

function bcc_trust_api_index() {

    $routes = rest_get_server()->get_routes('bcc-trust/v1');

    $endpoints = [];

    foreach ($routes as $route => $handlers) {

        foreach ($handlers as $handler) {

            $methods = [];

            if (isset($handler['methods'])) {

                if (is_array($handler['methods'])) {

                    $methods = array_keys($handler['methods']);

                } else {

                    $methods = [$handler['methods']];

                }

            }

            $callback = 'unknown';

            if (isset($handler['callback'])) {

                if (is_array($handler['callback'])) {

                    $callback = get_class($handler['callback'][0]) . '::' . $handler['callback'][1];

                } elseif (is_string($handler['callback'])) {

                    $callback = $handler['callback'];

                }

            }

            $endpoints[] = [

                'route' => $route,

                'methods' => $methods,

                'callback' => $callback

            ];
        }
    }

    return new WP_REST_Response([

        'success' => true,

        'data' => [

            'namespace' => 'bcc-trust/v1',

            'routes' => $endpoints

        ]

    ], 200);
}