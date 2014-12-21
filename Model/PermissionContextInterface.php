<?php

namespace Problematic\AclManagerBundle\Model;

use Symfony\Component\Security\Acl\Model\AuditableEntryInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;

interface PermissionContextInterface
{
    /**
     * @return int
     */
    public function getMask();

    /**
     * @return SecurityIdentityInterface
     */
    public function getSecurityIdentity();

    /**
     * @return mixed
     */
    public function getPermissionType();

    /**
     * @return array
     */
    public function getFields();

    /**
     * @return bool
     */
    public function isGranting();

    /**
     * @param AuditableEntryInterface $ace
     */
    public function equals(AuditableEntryInterface $ace);

    /**
     * @param AuditableEntryInterface $ace
     */
    public function hasDifferentPermission(AuditableEntryInterface $ace);
}
