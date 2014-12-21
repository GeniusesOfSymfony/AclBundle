<?php

namespace Problematic\AclManagerBundle\Domain;

use Problematic\AclManagerBundle\Model\PermissionContextInterface;
use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

class PermissionContext implements PermissionContextInterface
{
    /**
     * @var int
     */
    protected $permissionMask;

    /**
     * @var SecurityIdentityInterface
     */
    protected $securityIdentity;

    /**
     * @var string
     */
    protected $permissionType;

    /**
     * @var array
     */
    protected $fields;

    /**
     * @var bool
     */
    protected $granting;

    /**
     * @param integer $mask permission mask, or null for all
     */
    public function setMask($mask)
    {
        $this->permissionMask = $mask;
    }

    public function getMask()
    {
        return $this->permissionMask;
    }

    public function setSecurityIdentity(SecurityIdentityInterface $securityIdentity = null)
    {
        $this->securityIdentity = $securityIdentity;
    }

    public function getSecurityIdentity()
    {
        return $this->securityIdentity;
    }

    public function setPermissionType($type)
    {
        $this->permissionType = $type;
    }

    public function getPermissionType()
    {
        return $this->permissionType;
    }

    public function setGranting($granting)
    {
        $this->granting = $granting;
    }

    public function isGranting()
    {
        return $this->granting;
    }

    public function setFields(array $fields)
    {
        $this->fields = $fields;
    }

    public function getFields()
    {
        return $this->fields;
    }

    public function equals(AuditableEntryInterface $ace)
    {
        return $ace->getSecurityIdentity() == $this->getSecurityIdentity() &&
            $ace->isGranting() === $this->isGranting() &&
            $ace->getMask() === $this->getMask();
    }

    public function hasDifferentPermission(AuditableEntryInterface $ace)
    {
        return $ace->getSecurityIdentity() == $this->getSecurityIdentity() &&
            $ace->isGranting() === $this->isGranting() && $ace->getMask() !== $this->getMask();
    }
}
