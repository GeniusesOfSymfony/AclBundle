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
                $aclAlias = 'ta' . $key . '_';

                if ($extraQueries) {
                    $extraCriteriaSql = $this->parseExtraQueries($extraQueries, $tableAlias);
                    $aclSql = <<<ACL_SQL
INNER JOIN ({$query}) {$aclAlias} ON ({$tableAlias}.id = {$aclAlias}.id OR ({{$extraCriteriaSql}))
ACL_SQL;
                } else {
                    $aclSql = <<<ACL_SQL
INNER JOIN ({$query}) {$aclAlias} ON ({$tableAlias}.id = {$aclAlias}.id)
ACL_SQL;
                }

                $sql .= ' ' . $aclSql;
            }
        }

        return $sql;
    }

    /**
     * @param array $extraQueries
     * @param string $tableAlias
     *
     * @return array
     */
    protected function parseExtraQueries(Array $extraQueries, $tableAlias)
    {
        $clause = array();

        if(null === $extraQueries[0]){
            return false;
        }

        foreach($extraQueries as $query){
            $clause[] = $tableAlias.'.id IN(('.$query.'))';
        }

        return implode(' OR ', $clause);
    }
}
