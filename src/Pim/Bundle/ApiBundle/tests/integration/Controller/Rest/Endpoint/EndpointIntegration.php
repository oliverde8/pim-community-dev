<?php

namespace tests\integration\Pim\Bundle\ApiBundle\Controller\Rest\Family;

use Symfony\Component\HttpFoundation\Response;
use Test\Integration\TestCase;

class EndpointIntegration extends TestCase
{
    public function testGetEndpoint()
    {
        $client = static::createClient();

        $client->request('GET', 'api/rest/v1/');

        $endpoint = [
            'routes' => [
                '/api/rest/v1/categories/{code}' => [
                    'methods' => ['GET']
                ],
                '/api/rest/v1/families/{code}' => [
                    'methods' => ['GET']
                ],
                '/api/rest/v1/attributes/{code}' => [
                    'methods' => ['GET']
                ],
                '/api/rest/v1/' => [
                    'methods' => ['GET']
                ]
            ]
        ];

        $response = $client->getResponse();
        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame($endpoint, json_decode($response->getContent(), true));
    }
}
