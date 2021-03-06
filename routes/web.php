<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

/* AUTHENTICATION */ 
$router->post('/auth/register', 'AuthController@register');
$router->post('/auth/login', 'AuthController@login');
$router->get('/auth/Me', ['middleware' => 'auth', 'uses' => 'AuthController@me']);
$router->post('/auth/logout', ['middleware' => 'auth', 'uses' => 'AuthController@logout']);
