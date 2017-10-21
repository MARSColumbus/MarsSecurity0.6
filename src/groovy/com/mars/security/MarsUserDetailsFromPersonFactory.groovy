package com.mars.security

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class MarsUserDetailsFromPersonFactory implements UserDetailsFromDomainClassFactory {
	
	/**
	 * When using cas/ldap, the password attribute of the User object means nothing.
	 */
	private static final String NON_EXISTENT_PASSWORD_VALUE = "NO_PASSWORD"
	private static final String NON_EXISTENT_PHOTO_FILENAME = "no-photo-avatar.png"
	
	@Override
	UserDetails createUserDetails(Object domainClass,
			Collection<GrantedAuthority> authorities) {

		def conf = SpringSecurityUtils.securityConfig

		String usernamePropertyName = conf.userLookup.usernamePropertyName
		String username = domainClass."$usernamePropertyName"
		
		new MarsUser(username,
						NON_EXISTENT_PASSWORD_VALUE,
						true,
						true,
						true,
						true,
						authorities,
						domainClass.id,
						domainClass.fullName,
						domainClass.email,
						domainClass.photoFilename == null ? NON_EXISTENT_PHOTO_FILENAME : domainClass.photoFilename)
	}
}
