<?php

namespace Problematic\AclManagerBundle\RetrievalStrategy;

use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\ObjectIdentityRetrievalStrategy;

/**
 * @author Johann Saunier <johann_27@hotmail.fr>
 */
class AclObjectRetrievalStrategy extends ObjectIdentityRetrievalStrategy implements AclObjectIdentityRetrievalStrategyInterface
{
    /**
     * @var string
     */
    protected $type;

    /**
     * @param string $type
     */
    public function setType($type)
    {
        $this->type = $type;
    }

    /**
     * @param object $domainObject
     *
     * @return ObjectIdentity|\Symfony\Component\Security\Acl\Model\ObjectIdentityInterface|void
     * @throws \Exception
     */
    public function getObjectIdentity($domainObject)
    {
        if('class' === $this->type){
            if(is_object($domainObject)){
                return new ObjectIdentity($this->type, get_class($domainObject));
            }

            if(is_string($domainObject)){
                return new ObjectIdentity($this->type, $domainObject);
            }

            throw new \Exception('Undefined type, can\'t retrieve oid');
        }

        if('object' === $this->type){
            return parent::getObjectIdentity($domainObject);
        }
    }
}
