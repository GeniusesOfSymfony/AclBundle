<?php

namespace Problematic\AclManagerBundle\ORM;

use Doctrine\ORM\Query\SqlWalker;

class AclWalker extends SqlWalker
{
    /**
     * @param $fromClause
     *
     * @return string
     */
    public function walkFromClause($fromClause)
    {
        $sql = parent::walkFromClause($fromClause);
        $aclMetadata = $this->getQuery()->getHint('acl.metadata');
        $extraQueries = $this->getQuery()->getHint(AclFilter::HINT_ACL_EXTRA_CRITERIA);

        if ($aclMetadata) {
            foreach ($aclMetadata as $key => $metadata) {
                $alias = $metadata['alias'];
                $query = $metadata['query'];
                $table = $metadata['table'];
                $tableAlias = $this->getSQLTableAlias($table, $alias);
                $this->parseExtraQueries($extraQueries, $tableAlias);
                $aclAlias = 'ta' . $key . '_';

                $aclSql = <<<ACL_SQL
INNER JOIN ({$query}) {$aclAlias} ON ({$tableAlias}.id = {$aclAlias}.id OR ({$this->parseExtraQueries($extraQueries, $tableAlias)}))
ACL_SQL;
                $sql .= ' ' . $aclSql;
            }
        }

        return $sql;
    }

    /**
     * @param array  $extraQueries
     * @param string $tableAlias
     *
     * @return array
     */
    protected function parseExtraQueries(Array $extraQueries, $tableAlias)
    {
        $clause = array();

        foreach ($extraQueries as $query) {
            $clause[] = $tableAlias . '.id IN((' . $query . '))';
        }

        return implode(' OR ', $clause);
    }
}
