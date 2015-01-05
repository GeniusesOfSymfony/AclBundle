<?php

namespace Problematic\AclManagerBundle\ORM;

use Doctrine\Common\Persistence\AbstractManagerRegistry;
use Doctrine\Common\Persistence\Mapping\ClassMetadata;
use Doctrine\ORM\AbstractQuery;
use Doctrine\ORM\Query;
use Doctrine\ORM\QueryBuilder;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AclFilter
{
    const HINT_ACL_EXTRA_CRITERIA = 'acl_extra_criteria';

    /**
     * Construct AclFilter
     *
     * @param AbstractManagerRegistry  $doctrine
     * @param SecurityContextInterface $securityContext
     * @param array                    $options
     */
    public function __construct(
        AbstractManagerRegistry $doctrine,
        SecurityContextInterface $securityContext,
        Array $options = array()
    ) {
        $this->em = $doctrine->getManager();
        $this->securityContext = $securityContext;
        $this->aclConnection = $doctrine->getConnection('default');
        list($this->aclWalker, $this->roleHierarchy) = $options;
    }

    /**
     * Apply ACL filter
     *
     * @param  QueryBuilder | Query   $query
     * @param  array                  $permissions
     * @param  string | UserInterface $identity
     * @param  string                 $alias
     * @return Query
     */
    public function apply(
        $query,
        array $permissions = array('VIEW'),
        $identity = null,
        $alias = null,
        $extraCriteria = false
    ) {
        if (null === $identity) {
            $token = $this->securityContext->getToken();
            $identity = $token->getUser();
        }

        if (!is_array($extraCriteria)) {
            $extraCriteria = array($extraCriteria);
        }

        $sqlQueries = [];
        foreach ($extraCriteria as $criteria) {
            if ($criteria instanceof QueryBuilder) {
                $sqlQueries[] = $criteria->getQuery()->getSQL();
            } elseif ($criteria instanceof Query) {
                $sqlQueries[] = $criteria->getSQL();
            } else {
                $sqlQueries[] = $criteria;
            }
        }

        $query->setHint(static::HINT_ACL_EXTRA_CRITERIA, $sqlQueries);

        if ($query instanceof QueryBuilder) {
            $query = $this->cloneQuery($query->getQuery());
        } elseif ($query instanceof Query) {
            $query = $this->cloneQuery($query);
        } else {
            throw new \Exception();
        }

        $maskBuilder = new MaskBuilder();
        foreach ($permissions as $permission) {
            $mask = constant(get_class($maskBuilder) . '::MASK_' . strtoupper($permission));
            $maskBuilder->add($mask);
        }

        $entity = ($this->getEntityFromAlias($query, $alias));
        $metadata = $entity['metadata'];
        $alias = $entity['alias'];
        $table = $metadata->getQuotedTableName($this->em->getConnection()->getDatabasePlatform());

        $aclQuery = $this->getExtraQuery(
            $this->getClasses($metadata),
            $this->getIdentifiers($identity),
            $maskBuilder->get()
        );

        $hintAclMetadata = (false !== $query->getHint('acl.metadata'))
            ? $query->getHint('acl.metadata')
            : array();

        $hintAclMetadata[] = array('query' => $aclQuery, 'table' => $table, 'alias' => $alias);

        $query->setHint('acl.metadata', $hintAclMetadata);
        $query->setHint(Query::HINT_CUSTOM_OUTPUT_WALKER, $this->aclWalker);

        return $query;
    }

    /**
     * Get ACL filter SQL
     *
     * @param  array   $classes
     * @param  array   $identifiers
     * @param  integer $mask
     * @param  array   $extraCriteria
     * @return string
     */
    private function getExtraQuery(Array $classes, Array $identifiers, $mask)
    {
        $database = $this->aclConnection->getDatabase();
        $inClasses = implode(",", $classes);
        $inIdentifiers = implode(",", $identifiers);

        $query = <<<SELECTQUERY
SELECT DISTINCT o.object_identifier as id FROM {$database}.acl_object_identities as o
    INNER JOIN {$database}.acl_classes c ON c.id = o.class_id
    LEFT JOIN {$database}.acl_entries e ON (
        e.class_id = o.class_id AND (e.object_identity_id = o.id OR {$this->aclConnection->getDatabasePlatform()->getIsNullExpression('e.object_identity_id')})
    )
    LEFT JOIN {$database}.acl_security_identities s ON (
        s.id = e.security_identity_id
    )
    WHERE c.class_type IN ({$inClasses})
        AND s.identifier IN ({$inIdentifiers})
        AND e.mask >= {$mask}
SELECTQUERY;

        return $query;
    }

    /**
     * Resolve DQL alias into class metadata
     *
     * @param  AbstractQuery $query
     * @param  string        $alias
     * @return array         | null
     */
    protected function getEntityFromAlias(AbstractQuery $query, $alias = null)
    {
        $em = $query->getEntityManager();
        $ast = $query->getAST();
        $fromClause = $ast->fromClause;
        foreach ($fromClause->identificationVariableDeclarations as $root) {
            $className = $root->rangeVariableDeclaration->abstractSchemaName;
            $classAlias = $root->rangeVariableDeclaration->aliasIdentificationVariable;
            if (($classAlias == $alias) || (null === $alias)) {
                return array('alias' => $classAlias,
                    'metadata' => $em->getClassMetadata($className), );
            } else {
                foreach ($root->joins as $join) {
                    $joinAlias = $join->joinAssociationDeclaration->aliasIdentificationVariable;
                    $joinField = $join->joinAssociationDeclaration->joinAssociationPathExpression->associationField;
                    if ($joinAlias == $alias) {
                        $metadata = $em->getClassMetadata($className);
                        $joinName = $metadata->associationMappings[$joinField]['targetEntity'];

                        return array('alias' => $joinAlias,
                            'metadata' => $em->getClassMetadata($joinName), );
                    }
                }
            }
        }
    }

    /**
     * Get ACL compatible classes for specified class metadata
     *
     * @param  ClassMetadata $metadata
     * @return array
     */
    protected function getClasses(ClassMetadata $metadata)
    {
        $classes = array();
        foreach ($metadata->subClasses as $subClass) {
            $classes[] = '"' . str_replace('\\', '\\\\', $subClass) . '"';
        }
        $classes[] = '"' . str_replace('\\', '\\\\', $metadata->name) . '"';

        return $classes;
    }

    /**
     * Get security identifiers associated with specified identity
     *
     * @param  UserInterface | string $identity
     * @return array
     */
    protected function getIdentifiers($identity)
    {
        $userClass = array();
        if ($identity instanceof UserInterface) {
            $roles = $identity->getRoles();
            $userClass[] = '"' . str_replace('\\', '\\\\', get_class($identity)) . '-' . $identity->getUserName() . '"';
        } elseif (is_string($identity)) {
            $roles = array($identity);
        } else {
            return array();
        }
        $resolvedRoles = array();
        foreach ($roles as $role) {
            $resolvedRoles[] = '"' . $role . '"';
            $resolvedRoles = array_merge($resolvedRoles, $this->resolveRoles($role));
        }
        $identifiers = array_merge($userClass, array_unique($resolvedRoles));

        return $identifiers;
    }

    /**
     * Clone query
     *
     * @param  AbstractQuery $query
     * @return AbstractQuery
     */
    protected function cloneQuery(AbstractQuery $query)
    {
        $aclAppliedQuery = clone $query;
        $params = $query->getParameters();
        foreach ($params as $key => $param) {
            $aclAppliedQuery->setParameter($key, $param);
        }

        return $query;
    }

    /**
     * Get parent roles of the specified role
     *
     * @param  string $role
     * @return array
     */
    protected function resolveRoles($role)
    {
        $hierarchy = $this->roleHierarchy;
        $roles = array();
        if (array_key_exists($role, $hierarchy)) {
            foreach ($hierarchy[$role] as $parent_role) {
                $roles[] = '"' . $parent_role . '"';
                $roles = array_merge($roles, $this->resolveRoles($parent_role));
            }
        }

        return $roles;
    }
}
