<?php

namespace Problematic\AclManagerBundle\Domain;

use Doctrine\DBAL\Connection;
use Problematic\AclManagerBundle\Model\AclManagerInterface;
use Problematic\AclManagerBundle\Model\PermissionContextInterface;
use Problematic\AclManagerBundle\RetrievalStrategy\AclObjectIdentityRetrievalStrategyInterface;
use Symfony\Component\Security\Acl\Domain\Entry;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Exception\AclAlreadyExistsException;
use Symfony\Component\Security\Acl\Model\MutableAclInterface;
use Symfony\Component\Security\Acl\Model\MutableAclProviderInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Permission\MaskBuilder;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * abstract class containing low-level functionality (plumbing) to be extended by production AclManager (porcelain)
 * note that none of the methods in the abstract class call AclProvider#updatedAcl(); this needs to be taken care
 * of in the concrete implementation
 */
abstract class AbstractAclManager implements AclManagerInterface
{
    /**
     * @var MutableAclProviderInterface
     */
    protected $aclProvider;

    /**
     * @var SecurityContextInterface
     */
    protected $securityContext;

    /**
     * @var AclObjectIdentityRetrievalStrategyInterface
     */
    protected $objectIdentityRetrievalStrategy;

    /**
     * @var Connection
     */
    protected $connection;

    /**
     * @param MutableAclProviderInterface                 $aclProvider
     * @param SecurityContextInterface                    $securityContext
     * @param AclObjectIdentityRetrievalStrategyInterface $objectIdentityRetrievalStrategy
     * @param Connection                                  $connection
     */
    public function __construct(
        MutableAclProviderInterface $aclProvider,
        SecurityContextInterface $securityContext,
        AclObjectIdentityRetrievalStrategyInterface $objectIdentityRetrievalStrategy,
        Connection $connection
    ) {
        $this->aclProvider = $aclProvider;
        $this->securityContext = $securityContext;
        $this->objectIdentityRetrievalStrategy = $objectIdentityRetrievalStrategy;
        $this->connection = $connection;
    }

    /**
     * @return MutableAclProviderInterface
     */
    public function getAclProvider()
    {
        return $this->aclProvider;
    }

    /**
     * @return SecurityContextInterface
     */
    protected function getSecurityContext()
    {
        return $this->securityContext;
    }

    /**
     * @return AclObjectIdentityRetrievalStrategyInterface
     */
    protected function getObjectIdentityRetrievalStrategy()
    {
        return $this->objectIdentityRetrievalStrategy;
    }

    /**
     * Loads an ACL from the ACL provider, first by attempting to create, then finding if it already exists
     *
     * @param ObjectIdentityInterface $objectIdentity
     *
     * @return MutableAclInterface
     */
    protected function doLoadAcl(ObjectIdentityInterface $objectIdentity)
    {
        $acl = null;

        try {
            $acl = $this->getAclProvider()->createAcl($objectIdentity);
        } catch (AclAlreadyExistsException $ex) {
            $acl = $this->getAclProvider()->findAcl($objectIdentity);
        }

        return $acl;
    }

    /**
     * @param ObjectIdentityInterface|TokenInterface $token
     */
    protected function doRemoveAcl($token)
    {
        if (!$token instanceof ObjectIdentityInterface) {
            $token = ObjectIdentity::fromDomainObject($token);
        }

        $this->getAclProvider()->deleteAcl($token);
    }

    /**
     * Returns an instance of PermissionContext. If !$securityIdentity instanceof SecurityIdentityInterface, a new security identity will be created using it
     *
     * @param  string            $type
     * @param  string|string[]            $fields
     * @param $securityIdentity
     * @param  integer           $mask
     * @param  boolean           $granting
     * @return PermissionContext
     */
    protected function doCreatePermissionContext($type, $fields, $securityIdentity = null, $mask = null, $granting = true)
    {
        if(!is_array($fields)){
            $fields = (array) $fields;
        }

        $permissionContext = new PermissionContext();
        $permissionContext->setPermissionType($type);
        $permissionContext->setFields($fields);
        $permissionContext->setSecurityIdentity($securityIdentity);
        $permissionContext->setMask($mask);
        $permissionContext->setGranting($granting);

        return $permissionContext;
    }

    /**
     * Creates a new object instanceof SecurityIdentityInterface from input implementing one of UserInterface, TokenInterface or RoleInterface (or its string representation)
     *
     * @param  mixed                     $identity
     * @throws \InvalidArgumentException
     *
     * @return SecurityIdentityInterface
     */
    protected function doCreateSecurityIdentity($identity = null)
    {
        if(null === $identity){
            $identity = $this->getUser();
        }

        if($identity instanceof SecurityIdentityInterface){
            return $identity;
        }

        if (!$identity instanceof UserInterface && !$identity instanceof TokenInterface && !$identity instanceof RoleInterface && !is_string($identity)) {
            throw new \InvalidArgumentException(sprintf('$identity must implement one of: UserInterface, TokenInterface, RoleInterface (%s given)', get_class($identity)));
        }

        $securityIdentity = null;
        if ($identity instanceof UserInterface) {
            $securityIdentity = UserSecurityIdentity::fromAccount($identity);
        } elseif ($identity instanceof TokenInterface) {
            $securityIdentity = UserSecurityIdentity::fromToken($identity);
        } elseif ($identity instanceof RoleInterface || is_string($identity)) {
            $securityIdentity = new RoleSecurityIdentity($identity);
        }

        if (!$securityIdentity instanceof SecurityIdentityInterface) {
            throw new \InvalidArgumentException('Couldn\'t create a valid SecurityIdentity with the provided identity information');
        }

        return $securityIdentity;
    }

    /**
     * Loads an ACE collection from the ACL and updates the permissions (creating if no appropriate ACE exists)
     * @param MutableAclInterface        $acl
     * @param PermissionContextInterface $context
     * @param bool                       $replaceExisting
     *
     * @throws \Doctrine\DBAL\ConnectionException
     * @throws \Exception
     */
    protected function doApplyPermission(MutableAclInterface $acl, PermissionContextInterface $context, $replaceExisting = false)
    {
        $type = $context->getPermissionType();
        $this->connection->beginTransaction();

        try{
            $fields = $context->getFields();
            if(empty($fields)){
                $aceCollection = $this->getAceCollection($acl, $type);
                $size = count($aceCollection) - 1;
                reset($aceCollection);

                $this->doUpdatePermission($size, $replaceExisting, $aceCollection, $context, $acl, null, $type);
            }else{
                foreach($context->getFields() as $field){
                    $aceCollection = $this->getFieldAceCollection($acl, $type, $field);

                    $size = count($aceCollection) - 1;
                    reset($aceCollection);

                    $this->doUpdatePermission($size, $replaceExisting, $aceCollection, $context, $acl, $field, $type);
                }
            }

            $this->connection->commit();
        } catch(\Exception $e){
            $this->connection->rollBack();

            throw $e;
        }
    }

    /**
     * @param int                           $size
     * @param bool                           $replaceExisting
     * @param array                           $aceCollection
     * @param PermissionContextInterface $context
     * @param string                           $acl
     * @param string                           $field
     * @param string                           $type
     */
    protected function doUpdatePermission($size, $replaceExisting, $aceCollection, PermissionContextInterface $context, $acl, $field, $type)
    {
        for ($i = $size; $i >= 0; $i--) {
            if (true === $replaceExisting) {
                // Replace all existing permissions with the new one
                if ($context->hasDifferentPermission($aceCollection[$i])) {
                    // The ACE was found but with a different permission. Update it.
                    if (null === $field) {
                        $acl->{"update{$type}Ace"}($i, $context->getMask());
                    } else {
                        $acl->{"update{$type}FieldAce"}($i, $field, $context->getMask());
                    }

                    //No need to proceed further because the acl is updated
                    return;
                } else {
                    if ($context->equals($aceCollection[$i])) {
                        // The exact same ACE was found. Nothing to do.
                        return;
                    }
                }
            } else {
                if ($context->equals($aceCollection[$i])) {
                    // The exact same ACE was found. Nothing to do.
                    return;
                }
            }
        }

        if(null === $securityIdentity = $context->getSecurityIdentity()){
            $securityIdentity = $this->doCreateSecurityIdentity();
        }

        //If we come this far means we have to insert ace
        if (null === $field) {
            $acl->{"insert{$type}Ace"}(
                $securityIdentity,
                $context->getMask(),
                0,
                $context->isGranting()
            );
        } else {
            $acl->{"insert{$type}FieldAce"}(
                $field,
                $securityIdentity,
                $context->getMask(),
                0,
                $context->isGranting()
            );
        }
    }

    /**
     * @param MutableAclInterface        $acl
     * @param PermissionContextInterface $context
     *
     * @throws \Doctrine\DBAL\ConnectionException
     * @throws \Exception
     */
    protected function doRevokePermission(MutableAclInterface $acl, PermissionContextInterface $context)
    {
        $type = $context->getPermissionType();
        $fields = $context->getFields();
        $isTransactionActive = $this->connection->isTransactionActive();

        if(!$isTransactionActive){
            $this->connection->beginTransaction();
        }

        try{
            if(null === $fields || empty($fields)){
                $aceCollection = $this->getAceCollection($acl, $type);

                $found = false;
                $size = count($aceCollection) - 1;
                reset($aceCollection);

                for ($i = $size; $i >= 0; $i--) {
                    /** @var Entry $ace */
                    $ace = $aceCollection[$i];

                    if(null === $context->getSecurityIdentity() || $ace->getSecurityIdentity() === $context->getSecurityIdentity()){
                        if ($context->equals($ace)) {
                            $acl->{"delete{$type}Ace"}($i);
                            $found = true;
                        }
                    }
                }

                if (false === $found) {
                    // create a non-granting ACE for this permission

                    if(null === $securityIdentity = $context->getSecurityIdentity()){
                        $securityIdentity = $this->doCreateSecurityIdentity();
                    }

                    $newContext = $this->doCreatePermissionContext(
                        $context->getPermissionType(),
                        null,
                        $securityIdentity,
                        $context->getMask(),
                        false
                    );

                    $this->doApplyPermission($acl, $newContext);
                }
            }else {
                $aceCollection = array();

                foreach ($fields as $field) {
                    foreach ($this->getFieldAceCollection($acl, $type, $field) as $ace) {
                        $aceCollection[] = $ace;
                    }
                }

                $found = false;
                $size = count($aceCollection) - 1;
                reset($aceCollection);

                foreach ($fields as $field) {
                    for ($i = $size; $i >= 0; $i--) {
                        /** @var Entry $ace */
                        $ace = $aceCollection[$i];

                        if ($context->equals($ace)) {
                            $acl->{"delete{$type}FieldAce"}($i, $field);
                            $found = true;
                        }
                    }

                    if (false === $found) {
                        $newContext = $this->doCreatePermissionContext(
                            $context->getPermissionType(),
                            $field,
                            $context->getSecurityIdentity(),
                            $context->getMask(),
                            false
                        );

                        $this->doApplyPermission($acl, $newContext);
                    }
                }
            }

            if(!$isTransactionActive){
                $this->connection->commit();
            }
        } catch(\Exception $e){
            if(!$isTransactionActive){
                $this->connection->rollBack();
            }

            throw $e;
        }
    }

    /**
     * @param MutableAclInterface        $acl
     * @param PermissionContextInterface $context
     *
     * @throws \Doctrine\DBAL\ConnectionException
     * @throws \Exception
     */
    protected function doRevokeAllPermissions(MutableAclInterface $acl, PermissionContextInterface $context)
    {
        $isActiveTransaction = $this->connection->isTransactionActive();
        $fields = $context->getFields();

        if(!$isActiveTransaction){
            $this->connection->beginTransaction();
        }

        if (null === $fields || empty($fields)) {
            $aceCollection = $this->getAceCollection($acl, $context->getPermissionType());

            $size = count($aceCollection) - 1;
            reset($aceCollection);

            try{
                for ($i = $size; $i >= 0; $i--) {

                    /** @var Entry $ace */
                    $ace = $aceCollection[$i];

                    if(null === $context->getSecurityIdentity() || $ace->getSecurityIdentity() === $context->getSecurityIdentity()){
                        $acl->{"delete{$context->getPermissionType()}Ace"}($i);
                    }
                }

                if(!$isActiveTransaction){
                    $this->connection->commit();
                }
            } catch(\Exception $e){
                if(!$isActiveTransaction){
                    $this->connection->rollBack();
                }
                throw $e;
            }
        } else {
            try{
                foreach($fields as $field){
                    $aceCollection = $this->getFieldAceCollection($acl, $context->getPermissionType(), $field);

                    $size = count($aceCollection) - 1;
                    reset($aceCollection);

                    for ($i = $size; $i >= 0; $i--) {
                        /** @var Entry $ace */
                        $ace = $aceCollection[$i];

                        if(null === $context->getSecurityIdentity() || $ace->getSecurityIdentity() === $context->getSecurityIdentity()){
                            $acl->{"delete{$context->getPermissionType()}FieldAce"}($i, $field);
                        }
                    }
                }

                if(!$isActiveTransaction){
                    $this->connection->commit();
                }
            } catch(\Exception $e){
                if(!$isActiveTransaction){
                    $this->connection->rollBack();
                }

                throw $e;
            }

        }
    }

    /**
     * @param MutableAclInterface $acl
     * @param string              $type
     *
     * @return mixed
     */
    protected function getAceCollection(MutableAclInterface $acl, $type = 'object')
    {
        $aceCollection = $acl->{"get{$type}Aces"}();

        return $aceCollection;
    }

    /**
     * @param MutableAclInterface $acl
     * @param string              $type
     * @param string              $field
     *
     * @return mixed
     */
    protected function getFieldAceCollection(MutableAclInterface $acl, $type = 'object', $field)
    {
        $aceCollection = $acl->{"get{$type}FieldAces"}($field);

        return $aceCollection;
    }

    /**
     * @param string|string[]|int $attributes
     *
     * @return int
     */
    protected function buildMask($attributes)
    {
        if(is_int($attributes)){ //it's already a mask
            return $attributes;
        }

        if(!is_array($attributes)){
            $attributes = (array) $attributes;
        }

        $maskBuilder = new MaskBuilder();

        foreach($attributes as $attribute){
            $maskBuilder->add($attribute);
        }

        return $maskBuilder->get();
    }
}
