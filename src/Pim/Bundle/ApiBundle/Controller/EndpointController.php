<?php

namespace Pim\Bundle\ApiBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Routing\Router;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * @author    Marie Bochu <marie.bochu@akeneo.com>
 * @copyright 2017 Akeneo SAS (http://www.akeneo.com)
 * @license   http://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */
class EndpointController
{
    /** @var Router */
    protected $router;

    /**
     * @param Router $router
     */
    public function __construct(Router $router)
    {
        $this->router = $router;
    }

    public function getAction(Request $request)
    {
        $routes = $this->router->getRouteCollection();

        $apiRoutes = [];
        foreach ($routes as $key => $route) {
            if (0 === strpos($route->getPath(), '/api')) {
                $apiRoutes['routes'][$route->getPath()] = [
                    'methods' => $route->getMethods(),
                ];
            }
        }

        return new JsonResponse($apiRoutes);
    }
}
