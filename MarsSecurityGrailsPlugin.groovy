import net.sourceforge.jtds.jdbcx.JtdsDataSource

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.springframework.security.ldap.DefaultSpringSecurityContextSource
import org.springframework.security.ldap.authentication.BindAuthenticator
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch

import com.mars.security.DomainUserMapperService
import com.mars.security.MarsUserDetailsFromPersonFactory
import com.mars.security.MarsUserService
import com.mars.security.UserRoleService

class MarsSecurityGrailsPlugin {
    // the plugin version
    def version = "0.6"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "2.2 > *"
	List loadAfter = ['springSecurityCore']
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
        "grails-app/views/error.gsp"
    ]

    def title = "Mars Security Plugin" // Headline display name of the plugin
    def author = "Daniel Bower"
    def authorEmail = "daniel.bower@infinum.com"
    def description = '''\
Security Implementation for Mars Grails Apps
'''

	// URL to the plugin's documentation
	def documentation = "http://grails.org/plugin/mars-security"

	def doWithSpring = {
		
		xmlns security:"http://www.springframework.org/schema/security"
		
		// Implement runtime spring config (optional)
		
		def conf = SpringSecurityUtils.securityConfig
		
		if (!conf || !conf.active){
			return
		}
		println '\nConfiguring Mars LDAP ...'
			
		domainUserMapperService(DomainUserMapperService)

		userDetailsFromDomainClassFactory(MarsUserDetailsFromPersonFactory)

		casDataSource(JtdsDataSource)

		userRoleService(UserRoleService){
			casDataSource = ref('casDataSource')
		}

		ldapUserDetailsMapper(MarsUserService)
		
		if(conf.ldap.enableLocal){
			println "Enabling local ldap ${conf.ldap.localcontext.server}" 
			
			security.'ldap-server'('ldif':'file:/usr/local/etc/mars/users.ldif')

			contextSourceLocal(DefaultSpringSecurityContextSource, 
					conf.ldap.local.context.server)

			ldapAuthenticatorLocal(BindAuthenticator, contextSourceLocal) {
				userDnPatterns = conf.ldap.local.context.userDnPatterns
			}
			
			ldapAuthProviderLocal(LdapAuthenticationProvider, 
					ldapAuthenticatorLocal) {
				userDetailsContextMapper = ref('ldapUserDetailsMapper')
				hideUserNotFoundExceptions = false
				useAuthenticationRequestCredentials = true
			}
			
			SpringSecurityUtils.registerProvider 'ldapAuthProviderLocal'
		
		}else{
			contextSourceCorp(DefaultSpringSecurityContextSource, 
					conf.ldap.corp.context.server){ 
				userDn = conf.ldap.corp.context.serverUser
				password = conf.ldap.corp.context.serverPassword
			}
			
			contextSourceKkc(DefaultSpringSecurityContextSource, 
					conf.ldap.kkc.context.server){ 
				userDn = conf.ldap.kkc.context.serverUser
				password = conf.ldap.kkc.context.serverPassword
			}

			filterBasedLdapUserSearchCorp(FilterBasedLdapUserSearch, 
					conf.ldap.corp.context.searchBase,
					conf.ldap.corp.context.searchFilter,
					contextSourceCorp)

			filterBasedLdapUserSearchKkc(FilterBasedLdapUserSearch, 
					conf.ldap.kkc.context.searchBase,
					conf.ldap.kkc.context.searchFilter,
					contextSourceKkc)

			ldapAuthenticatorCorp(BindAuthenticator, contextSourceCorp){
				userSearch = ref('filterBasedLdapUserSearchCorp')
			}
			
			ldapAuthenticatorKkc(BindAuthenticator, contextSourceKkc){
				userSearch = ref('filterBasedLdapUserSearchKkc')
			}
			
			ldapAuthProviderCorp(LdapAuthenticationProvider, 
					ldapAuthenticatorCorp) {
				userDetailsContextMapper = ref('ldapUserDetailsMapper')
				hideUserNotFoundExceptions = false
				useAuthenticationRequestCredentials = true
			}
			
			ldapAuthProviderKkc(LdapAuthenticationProvider, 
					ldapAuthenticatorKkc) {
				userDetailsContextMapper = ref('ldapUserDetailsMapper')
				hideUserNotFoundExceptions = false
				useAuthenticationRequestCredentials = true
			}
		
			SpringSecurityUtils.registerProvider 'ldapAuthProviderCorp'
			SpringSecurityUtils.registerProvider 'ldapAuthProviderKkc'
		}

	}
}
