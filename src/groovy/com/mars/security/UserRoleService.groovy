package com.mars.security

import groovy.sql.Sql

import javax.sql.DataSource

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.beans.factory.annotation.Autowired

class UserRoleService {

	DataSource casDataSource
	
	@Autowired
	GrailsApplication grailsApplication
		
	List<String> getUsernamesWithRole(String role) {
		Sql sql = new Sql(casDataSource)
		
		String sqlStatement = ""
		
		if (grailsApplication.config.casdbtype == "mssql"){
			sqlStatement = "select ur.username " +
						   "from UserRole ur " +
						   		"inner join Role r on ur.role_id = r.id " +
						   "where r.name=:roleName"
		}else{
			sqlStatement = 'select ur.username from userrole ur inner join role r on ur.role_id = r.id where r.name=:roleName'
		}
		
		List<String> usernamesWithRole = []
		sql.eachRow(sqlStatement, [roleName:role]){
			usernamesWithRole << it.username
		}
		
		usernamesWithRole
	}
	
	List<String> getRolesByUsername(String username) {
		Sql sql = new Sql(casDataSource)

		String sqlStatement = ""
		
		if (grailsApplication.config.casdbtype == "mssql"){
			sqlStatement = "select r.name " +
						   "from UserRole ur " +
						   		"inner join Role r on ur.role_id = r.id " +
						   "where ur.username = :username"
		}else{
			sqlStatement = "select r.name " +
						   "from userrole ur " +
						   		"inner join role r on ur.role_id = r.id " +
						   "where ur.username = :username"
		}
		
		List<String> rolesWithUsername = []
		
		sql.eachRow(sqlStatement, [username:username]) {
			rolesWithUsername << it.name
		}
		
		rolesWithUsername
	}
}
