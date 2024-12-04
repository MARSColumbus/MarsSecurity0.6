package com.mars.security

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

/**
 * Implement this class to turn a domain class into a custom UserDetails Object.
 *
 * The UserDetailsService will call this class with the user's
 * domain class object and authorities from CAS.
 *
 * @author daniel.d.bower
 */
interface UserDetailsFromDomainClassFactory {
	UserDetails createUserDetails(domainClass, Collection<GrantedAuthority> authorities)
}
