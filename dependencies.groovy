grails.project.work.dir = 'target'
//grails.project.class.dir = "target/classes"
//grails.project.test.class.dir = "target/test-classes"
//grails.project.test.reports.dir = "target/test-reports"

grails.project.dependency.resolution = {
    // inherit Grails' default dependencies
    inherits("global") {
        // uncomment to disable ehcache
        // excludes 'ehcache'
    }
    log "warn" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
    legacyResolve false // whether to do a secondary resolve on plugin installation, not advised and here for backwards compatibility
    repositories {
        grailsCentral()
        // uncomment the below to enable remote dependency resolution
        // from public Maven repositories
        mavenLocal()
        mavenCentral()
        //mavenRepo "http://snapshots.repository.codehaus.org"
        //mavenRepo "http://repository.codehaus.org"
        //mavenRepo "http://download.java.net/maven/2/"
        //mavenRepo "http://repository.jboss.com/maven2/"
    }
    dependencies {
        // specify dependencies here under either 'build', 'compile', 'runtime', 'test' or 'provided' scopes eg.

        // runtime 'mysql:mysql-connector-java:5.1.21'

		compile 'org.springframework.security:spring-security-ldap:3.0.7.RELEASE',
				'org.springframework.security:spring-security-config:3.0.7.RELEASE'
				
		runtime 'org.apache.directory.server:apacheds-core:1.5.5',
				'org.apache.directory.server:apacheds-protocol-ldap:1.5.5',
				'org.apache.directory.shared:shared-ldap:0.9.17'
		provided 'net.sourceforge.jtds:jtds:1.2.4'
    }

    plugins {
        build(":tomcat:$grailsVersion",
              ":release:2.2.1",
              ":rest-client-builder:1.0.3") {
            export = false
        }
   
        provided(":codenarc:0.20"){
            exclude "junit"
    }
	
		compile ':spring-security-core:1.2.7.3'
}
}

codenarc.ruleSetFiles="file:grails-app/conf/MarsSecurityCodeNarcRules.groovy"
codenarc.processTestUnit=false
codenarc.processTestIntegration=false
codenarc.reports = {
    xmlReport('xml') {
        outputFile = 'target/CodeNarc-Report.xml'
    }
    htmlReport('html') {
        outputFile = 'target/CodeNarc-Report.html'
    }
}

