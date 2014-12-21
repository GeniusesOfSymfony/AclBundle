<?php

namespace Problematic\AclManagerBundle\Model;

use Symfony\Component\Security\Acl\Model\DomainObjectInterface;
use Symfony\Component\Security\Acl\Model\MutableAclProviderInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\User\UserInterface;

interface AclManagerInterface
{
    /**
     * Sets permission mask for a given domain object. All previous permissions for this
     * user and this object will be over written. If none existed, a new one will be created.
     *
     * @param  mixed                                      $domainObject
     * @param  int|string|string[]                                        $mask
     * @param  string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface $securityIdentity if none given, the current session user will be used
     * @return self
     */
    public function addObjectPermission($domainObject, $mask, $securityIdentity = null);

    /**
     * Sets permission mask for a given class. All previous permissions for this
     * user and this class will be over written. If none existed, a new one will be created.
     *
     * @param  mixed                                      $domainObject
     * @param  int|string|string[]                                        $mask
     * @param  string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null $securityIdentity if none given, the current session user will be used
     * @return self
     */
    public function addClassPermission($domainObject, $mask, $securityIdentity = null);

    /** Set permission mask for a given field of a domain object. All previous permissions
     * for this user and this object will be over written. If none existed, a new one will be created.
     *
     * @param  mixed                                      $domainObject
     * @param  string                                     $fields
     * @param  int|string|string[]                                        $mask
     * @param  string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null $securityIdentity if none fiven, the current session user will be used
     * @return self
     */
    public function addObjectFieldPermission($domainObject, $fields, $mask, $securityIdentity = null);

    /** Set permission mask for a given field of a class. All previous permissions for this
     * user and this object will be over written. If none existed, a new one will be created.
     *
     * @param  mixed                                      $domainObject
     * @param  string|string[]                                     $fields
     * @param  int|string|string[]                                        $mask
     * @param  string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null if none given, the current session user will be used
     * @return self
     */
    public function addClassFieldPermission($domainObject, $fields, $mask, $securityIdentity = null);

    /**
     * Sets permission mask for a given domain object. All previous permissions for this
     * user and this object will be over written. If none existed, a new one will be created.
     *
     * @param mixed                                      $domainObject
     * @param int|string|string[]                                        $mask
     * @param string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null $securityIdentity if none given, the current session user will be used
     */
    public function setObjectPermission($domainObject, $mask, $securityIdentity = null);

    /**
     * Sets permission mask for a given class. All previous permissions for this
     * user and this class will be over written. If none existed, a new one will be created.
     *
     * @param mixed                                      $domainObject
     * @param int|string|string[]                                        $mask
     * @param string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null $securityIdentity if none given, the current session user will be used
     */
    public function setClassPermission($domainObject, $mask, $securityIdentity = null);

    /** Set permission mask for a given field of a domain object. All previous permissions
     * for this user and this object will be over written. If none existed, a new one will be created.
     *
     * @param mixed                                      $domainObject
     * @param string|string[]                                     $fields
     * @param int|string|string[]                                        $mask
     * @param string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null $securityIdentity if none fiven, the current session user will be used
     */
    public function setObjectFieldPermission($domainObject, $fields, $mask, $securityIdentity = null);

    /** Set permission mask for a given field of a class. All previous permissions for this
     * user and this object will be over written. If none existed, a new one will be created.
     *
     * @param mixed                                      $domainObject
     * @param string|string[]                                     $fields
     * @param int|string|string[]                                        $mask
     * @param string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null $securityIdentity if none fiven, the current session user will be used
     */
    public function setClassFieldPermission($domainObject, $fields, $mask, $securityIdentity = null);

    /**
     * @param mixed  $domainObject
     * @param string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null   $securityIdentity
     * @param string $type
     *
     * @return self
     */
    public function revokePermission($domainObject, $attributes, $securityIdentity = null, $type = 'object');

    /**
     * @param mixed  $domainObject
     * @param string|string[] $fields
     * @param string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null   $securityIdentity
     * @param string $type
     *
     * @return self
     */
    public function revokeFieldPermission($domainObject, $fields, $attributes, $securityIdentity = null, $type = 'object');

    /**
     * @param mixed                                          $domainObject
     * @param string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null $securityIdentity if none given, the current session user will be used
     */
    public function revokeAllObjectPermissions($domainObject, $securityIdentity = null);

    /**
     * @param mixed                                          $domainObject
     * @param string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface if none given, the current session user will be used
     */
    public function revokeAllClassPermissions($domainObject, $securityIdentity = null);

    /**
     * @param mixed                                          $domainObject
     * @param string|string[]                                       $fields
     * @param string|UserInterface|TokenInterface|RoleInterface|SecurityIdentityInterface|null $securityIdentity if none given, the current session user will be used
     */
    public function revokeAllObjectFieldPermissions($domainObject, $fields, $securityIdentity = null);

    /**
     * @param mixed                                          $domainObject
     * @param string|string[]                                         $fields
     * @param UserInterface | TokenInterface | RoleInterface $securityIdentity if none given, the current session user will be used
     */
    public function revokeAllClassFieldPermissions($domainObject, $fields, $securityIdentity = null);

    /**
     * Pre Load Acls for all managed entries, that avoid doctrine to create N extra request.
     *
     * @param array $objects
     * @param array $identities
     *
     * @return \SplObjectStorage
     */
    public function preloadAcls($objects, $identities = array());

    /**
     * Delete entry related of item managed via ACL system
     *
     * @param string|DomainObjectInterface $managedItem
     *
     * @return self
     */
    public function deleteAclFor($managedItem, $type = 'class');

    /**
     * @param string|string[] $attributes
     * @param null|object     $object
     * @param string          $type
     *
     * @return bool
     */
    public function isGranted($attributes, $object = null, $type = 'object');

    /**
     * @param object          $object
     * @param string|string[]          $fields
     * @param string          $type
     *
     * @return bool
     */
    public function isFieldGranted($attributes, $object, $fields, $type = 'object');

    /**
     * Retrieves the current session user
     *
     * @return UserInterface
     */
    public function getUser();

    /**
     * @return MutableAclProviderInterface
     */
    public function getAclProvider();
}
