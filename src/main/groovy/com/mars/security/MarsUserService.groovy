package com.mars.security

import grails.gorm.transactions.Transactional
import org.slf4j.Logger
import grails.plugin.springsecurity.SpringSecurityUtils
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.ldap.core.DirContextAdapter
import org.springframework.ldap.core.DirContextOperations
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper
import groovy.sql.Sql

@Transactional
class MarsUserService implements UserDetailsContextMapper{

	private static final Logger LOGGER = LoggerFactory.getLogger(MarsUserService)

	/**
	 * Some Spring Security classes (e.g. RoleHierarchyVoter) expect at least one role, so
	 * we give a user with no granted roles this one which gets past that restriction but
	 * doesn't grant anything.
	 */
	private static final List NO_ROLES = [new SimpleGrantedAuthority(SpringSecurityUtils.NO_ROLE)]

	/** Dependency injection for creating and finding Users **/
	@Autowired
	DomainUserMapperService userMapper
	/** Dependency injection for creating userDetails objects **/
	@Autowired
	UserDetailsFromDomainClassFactory userDetailsFromDomainClassFactory

	@Autowired
	UserRoleService userRoleService

	@Override
	UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
		LOGGER.debug("BEGIN : mapUserFromContext(): $username")

		//look up user profile in database
		def user = userMapper.findUserByUsername(username)
		Map userAttributes = userAttribsFromLdapContext(ctx,username)

		//Create the user profile if it does not already exist
		if(!user){
			LOGGER.debug "User Attributes: $userAttributes"
			user = userMapper.newUser(
					username,
					userAttributes)
		}

		// Save user information to CAS database person table
		saveUserToCasDatabase(username, userAttributes.firstName, userAttributes.lastName, userAttributes.email == "No Email" ? null : userAttributes.email)

		authorities = authoritiesForUsername(username)

		return userDetailsFromDomainClassFactory.createUserDetails(user, authorities)
	}

	private Map userAttribsFromLdapContext(DirContextOperations ctx, String username){

		String firstName = ctx.getStringAttribute('givenName')
		String lastName= ctx.getStringAttribute('sn')
		String email = ctx.getStringAttribute('mail')?:'No Email'

		return[firstName:firstName, lastName:lastName, email:email]
	}

		/**
	 * Saves user information to the CAS database person table
	 */
	private void saveUserToCasDatabase(String username, String firstName, String lastName, String email) {
		try {
			// Use the same data source that's used for role lookups
			Sql sql = new Sql(userRoleService.casDataSource)

			// Check if user already exists in person table
			def existingPerson = sql.firstRow("SELECT * FROM person WHERE username = :username", [username: username])
			
			// Get current timestamp in SQL format
			java.sql.Timestamp currentTimestamp = new java.sql.Timestamp(System.currentTimeMillis())

			if (existingPerson) {
				// Update existing record
				sql.executeUpdate("""
					UPDATE person 
					SET first_name = :firstName, 
						last_name = :lastName, 
						email = :email,
						last_updated = :lastUpdated
					WHERE username = :username
				""", [
					firstName: firstName,
					lastName: lastName,
					email: email,
					lastUpdated: currentTimestamp,
					username: username
				])
				LOGGER.debug "Updated user $username in CAS person table"
			} else {
				// Insert new record
				sql.executeInsert("""
					INSERT INTO person (username, first_name, last_name, email, last_updated)
					VALUES (:username, :firstName, :lastName, :email, :lastUpdated)
				""", [
					username: username,
					firstName: firstName,
					lastName: lastName,
					email: email,
					lastUpdated: currentTimestamp
				])
				LOGGER.debug "Inserted user $username into CAS person table"
			}
		} catch (Exception e) {
			LOGGER.error "Failed to save user to CAS database: ${e.message}", e
			// Don't throw the exception - we still want authentication to succeed
		}
	}

	private Collection authoritiesForUsername(String username){
		List<String>roles = userRoleService.getRolesByUsername(username)

		if(!roles){
			return NO_ROLES
		}

		List authorities = []
		for(String role : roles){
			authorities << new SimpleGrantedAuthority(role)
		}

		LOGGER.debug "Authorities for $username : $roles"
		return authorities
	}

	void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
		// not implemented
	}
}
