<?php

namespace Problematic\AclManagerBundle\RetrievalStrategy;

use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\ObjectIdentityRetrievalStrategy;
use Symfony\Component\Security\Core\Util\ClassUtils;

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
     * @param object $object
     *
     * @return ObjectIdentity|\Symfony\Component\Security\Acl\Model\ObjectIdentityInterface|void
     * @throws \Exception
     */
    public function getObjectIdentity($object)
    {
        if ('class' === $this->type) {
            if (is_object($object)) {
                return new ObjectIdentity(ClassUtils::getRealClass($object), $this->type);
            }

            if (is_string($object)) {
                return new ObjectIdentity($object, $this->type);
            }

            throw new \Exception('Undefined type, can\'t retrieve oid');
        }

        if ('object' === $this->type) {
            return parent::getObjectIdentity($object);
        }

        throw new \Exception('Unknown type');
    }
}
