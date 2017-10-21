package com.mars.security

import org.apache.log4j.Logger
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.ldap.core.DirContextAdapter
import org.springframework.ldap.core.DirContextOperations
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper

class MarsUserService implements UserDetailsContextMapper{
	
	private static final Logger LOGGER = Logger.getLogger(MarsUserService)

	/**
	 * Some Spring Security classes (e.g. RoleHierarchyVoter) expect at least one role, so
	 * we give a user with no granted roles this one which gets past that restriction but
	 * doesn't grant anything.
	 */
	private static final List NO_ROLES = [new GrantedAuthorityImpl(SpringSecurityUtils.NO_ROLE)]
	
	/** Dependency injection for creating and finding Users **/
	@Autowired
	DomainUserMapperService userMapper
	/** Dependency injection for creating userDetails objects **/
	@Autowired
	UserDetailsFromDomainClassFactory userDetailsFromDomainClassFactory
	
	@Autowired
	UserRoleService userRoleService
	
	UserDetails mapUserFromContext(DirContextOperations ctx,
			String username, Collection<GrantedAuthority> authorities) {

		LOGGER.debug("BEGIN : mapUserFromContext(): $username")

		//look up user profile in database
		def user = userMapper.findUserByUsername(username)
		//Create the user profile if it does not already exist
		if(!user){
			
			Map userAttributes = userAttribsFromLdapContext(ctx,username)
			LOGGER.debug "User Attributes: $userAttributes"
			user = userMapper.newUser(
					username, 
					userAttributes)
		}
		
		authorities = authoritiesForUsername(username)
		
		return userDetailsFromDomainClassFactory.createUserDetails(user, authorities)
	}
			
	private Map userAttribsFromLdapContext(DirContextOperations ctx, String username){
		
		String firstName = ctx.getStringAttribute('givenName') 
		String lastName= ctx.getStringAttribute('sn') 
		String email = ctx.getStringAttribute('mail')?:'No Email'
		
		return[firstName:firstName, lastName:lastName, email:email]
	}
	
	private Collection authoritiesForUsername(String username){
		List<String>roles = userRoleService.getRolesByUsername(username)

		if(!roles){
			return NO_ROLES
		}
		
		List authorities = []
		for(String role : roles){
			authorities << new GrantedAuthorityImpl(role)
		}

		LOGGER.debug "Authorities for $username : $roles"
		return authorities
	}

	void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
		// not implemented
	}
}
