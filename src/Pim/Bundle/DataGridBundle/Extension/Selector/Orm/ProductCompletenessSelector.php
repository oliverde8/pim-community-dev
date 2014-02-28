<?php

namespace Pim\Bundle\DataGridBundle\Extension\Selector\Orm;

use Oro\Bundle\DataGridBundle\Datasource\DatasourceInterface;
use Oro\Bundle\DataGridBundle\Datagrid\Common\DatagridConfiguration;
use Pim\Bundle\DataGridBundle\Extension\Selector\SelectorInterface;
use Pim\Bundle\CatalogBundle\Entity\Repository\ProductRepository;

/**
 * Product completeness selector
 *
 * @author    Nicolas Dupont <nicolas@akeneo.com>
 * @copyright 2014 Akeneo SAS (http://www.akeneo.com)
 * @license   http://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */
class ProductCompletenessSelector implements SelectorInterface
{
    /**
     * @var ProductRepository
     */
    protected $repository;

    /**
     * @param ProductRepository $repository
     */
    public function __construct(ProductRepository $repository)
    {
        $this->repository = $repository;
    }

    /**
     * {@inheritdoc}
     */
    public function apply(DatasourceInterface $datasource, DatagridConfiguration $configuration)
    {
        $qb        = $datasource->getQueryBuilder();
        $joinAlias = 'selectCompleteness';

        $this->repository->addCompleteness($qb, $joinAlias);
        $qb->addSelect($joinAlias.'.ratio AS ratio');
    }
}
