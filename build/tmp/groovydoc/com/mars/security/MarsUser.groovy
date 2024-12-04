package com.mars.security

import grails.plugin.springsecurity.userdetails.GrailsUser
import org.springframework.security.core.GrantedAuthority

class MarsUser extends GrailsUser {

	String fullName
	String emailAddress
	String photoFilename

	MarsUser(String username, String password,
			boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<GrantedAuthority> authorities,
			Object id,
			String fullName, String emailAddress, String photoFilename) {

			super(username, password, enabled, accountNonExpired, credentialsNonExpired,
					accountNonLocked, authorities, id)

			this.fullName = fullName
			this.emailAddress = emailAddress
			this.photoFilename = photoFilename
	}
}
