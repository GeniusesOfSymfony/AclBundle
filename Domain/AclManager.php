<?php

namespace Problematic\AclManagerBundle\Domain;

use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Voter\FieldVote;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\AuthenticatedVoter;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AclManager extends AbstractAclManager
{
    /**
     * {@inheritDoc}
     */
    public function addObjectPermission($domainObject, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, null,  $mask, $securityIdentity, 'object', false);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function addClassPermission($domainObject, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, null, $mask, $securityIdentity, 'class', false);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function addObjectFieldPermission($domainObject, $fields, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, $fields, $mask, $securityIdentity, 'object', false);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function addClassFieldPermission($domainObject, $fields, $mask, $securityIdentity = null)
    {
        $this->addPermission($domainObject, $fields, $mask, $securityIdentity, 'class', false);

        return $this;
    }

    /**
     * @param  mixed                                      $domainObject
     * @param  string                                     $fields
     * @param  UserInterface|TokenInterface|RoleInterface $securityIdentity
     * @param  string                                     $type
     * @param  string                                     $fields
     * @param  boolean                                    $replaceExisting
     *
     * @return AbstractAclManager
     */
    protected function addPermission($domainObject, $fields, $attributes, $securityIdentity = null, $type = 'object', $replaceExisting = false)
    {
        $mask = $this->buildMask($attributes);

        $context = $this->doCreatePermissionContext(
            $type,
            $fields,
            $this->doCreateSecurityIdentity($securityIdentity),
            $mask
        );

        $acl = $this->doLoadAcl($this->doRetrieveObjectIdentity($domainObject, $type));

        $this->doApplyPermission($acl, $context, $replaceExisting);

        $this->getAclProvider()->updateAcl($acl);

        return $this;
    }

    /**
     * @param  mixed                                                   $domainObject
     * @param  int                                                     $mask
     * @param  UserInterface | TokenInterface | RoleInterface          $securityIdentity
     * @param  string                                                  $type
     * @param  string                                                  $fields
     * @return \Problematic\AclManagerBundle\Domain\AbstractAclManager
     */
    protected function setPermission($domainObject, $fields, $mask, $securityIdentity = null, $type = 'object')
    {
        $this->addPermission($domainObject, $fields, $mask, $securityIdentity, $type, true);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function setObjectPermission($domainObject, $mask, $securityIdentity = null)
    {
        $this->setPermission($domainObject, null, $mask, $securityIdentity, 'object');
    }

    /**
     * {@inheritDoc}
     */
    public function setClassPermission($domainObject, $mask, $securityIdentity = null)
    {
        $this->setPermission($domainObject, null, $mask, $securityIdentity, 'class');
    }

    /**
     * {@inheritDoc}
     */
    public function setObjectFieldPermission($domainObject, $fields, $mask, $securityIdentity = null)
    {
        $this->setPermission($domainObject, $fields, $mask, $securityIdentity, 'object');
    }

    /**
     * {@inheritDoc}
     */
    public function setClassFieldPermission($domainObject, $fields, $mask, $securityIdentity = null)
    {
        $this->setPermission($domainObject, $fields, $mask, $securityIdentity, 'class');
    }

    /**
     * {@inheritDoc}
     */
    public function revokePermission($domainObject, $attributes, $securityIdentity = null, $type = 'object')
    {
        if(null !== $securityIdentity){
           $securityIdentity = $this->doCreateSecurityIdentity($securityIdentity);
        }

        $context = $this->doCreatePermissionContext(
            $type,
            null,
            $securityIdentity,
            $this->buildMask($attributes)
        );

        $acl = $this->doLoadAcl($this->doRetrieveObjectIdentity($domainObject, $type));
        $this->doRevokePermission($acl, $context);
        $this->getAclProvider()->updateAcl($acl);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function revokeFieldPermission($domainObject, $fields, $attributes, $securityIdentity = null, $type = 'object')
    {
        if (null === $securityIdentity) {
            $securityIdentity = $this->doCreateSecurityIdentity($securityIdentity);
        }

        $context = $this->doCreatePermissionContext(
            $type,
            $fields,
            $securityIdentity,
            $this->buildMask($attributes)
        );

        $acl = $this->doLoadAcl($this->doRetrieveObjectIdentity($domainObject, $type));

        $this->doRevokePermission($acl, $context);
        $this->getAclProvider()->updateAcl($acl);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function revokeAllClassPermissions($domainObject, $securityIdentity = null)
    {
        $this->revokeAllPermissions($domainObject, null, $securityIdentity, 'class');
    }

    /**
     * {@inheritDoc}
     */
    public function revokeAllObjectPermissions($domainObject, $securityIdentity = null)
    {
        $this->revokeAllPermissions($domainObject, null, $securityIdentity, 'object');
    }

    /**
     * {@inheritDoc}
     */
    public function revokeAllClassFieldPermissions($domainObject, $fields, $securityIdentity = null)
    {
        $this->revokeAllPermissions($domainObject, $fields, $securityIdentity, 'class');
    }

    /**
     * {@inheritDoc}
     */
    public function revokeAllObjectFieldPermissions($domainObject, $fields, $securityIdentity = null)
    {
        $this->revokeAllPermissions($domainObject, $fields, $securityIdentity, 'object');
    }

    /**
     * @param mixed  $domainObject
     * @param string|string[] $fields
     * @param null|string|SecurityIdentityInterface|UserInterface   $securityIdentity
     * @param string $type
     *
     * @return $this
     */
    protected function revokeAllPermissions($domainObject, $fields, $securityIdentity = null, $type = 'object')
    {
        if (null !== $securityIdentity) {
            $securityIdentity = $this->doCreateSecurityIdentity($securityIdentity);
        }

        $context = $this->doCreatePermissionContext(
            $type,
            $fields,
            $securityIdentity
        );

        $oid = $this->doRetrieveObjectIdentity($domainObject, $type);
        $acl = $this->doLoadAcl($oid);
        $this->doRevokeAllPermissions($acl, $context);
        $this->getAclProvider()->updateAcl($acl);

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function preloadAcls($objects, $identities = array())
    {
        $oids = array();
        $objectIdentityRetriever = $this->getObjectIdentityRetrievalStrategy();

        foreach ($objects as $object) {
            $oids[] = $objectIdentityRetriever->getObjectIdentity($object);
        }

        $sids = array();

        foreach ($identities as $identity) {
            $sid = $this->doCreateSecurityIdentity($identity);
            $sids[] = $sid;
        }

        $acls = $this->getAclProvider()->findAcls($oids, $sids);

        return $acls;
    }

    /**
     * {@inheritDoc}
     */
    public function deleteAclFor($object, $type = 'class')
    {
        $this->getAclProvider()->deleteAcl($this->doRetrieveObjectIdentity($object, $type));
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function isGranted($attributes, $object = null, $type = 'object')
    {
        return $this->getSecurityContext()->isGranted(
            $attributes,
            $this->doRetrieveObjectIdentity($object, $type)
        );
    }

    /**
     * {@inheritDoc}
     */
    public function isFieldGranted($attributes, $object, $fields, $type = 'object')
    {
        if(!is_array($fields)){
            $fields = array($fields);
        }

        $oid = $this->doRetrieveObjectIdentity($object, $type);
        $fieldGranted = array();

        foreach($fields as $field){
            if(true === $this->getSecurityContext()->isGranted($attributes, new FieldVote($oid, $field))){
                $fieldGranted[$field] = true;
            }
        }

        return count($fields) === count($fieldGranted);
    }

    protected function doRetrieveObjectIdentity($object, $type)
    {
        if($object instanceof ObjectIdentityInterface){
            $oid = $object;
        }else{
            $objectIdentityRetriever = $this->getObjectIdentityRetrievalStrategy();
            $objectIdentityRetriever->setType($type);
            $oid = $objectIdentityRetriever->getObjectIdentity($object);
        }

        return $oid;
    }

    /**
     * {@inheritDoc}
     */
    public function getUser()
    {
        $token = $this->getSecurityContext()->getToken();

        if (null === $token) {
            return;
        }

        if(false === $token->isAuthenticated()){
            return AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY;
        }

        return $token->getUser();
    }
}
