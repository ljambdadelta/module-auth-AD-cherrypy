# module-auth-AD-cherrypy
Module written for cherrypy to provide simple auth from Active Directory server via LDAP.

Status is "works fine but has huge issues"

Probably would work with different server engines but it was written with cherrypy in mind.

You give:
sAMAccountName, password, server address, AD domain and cherrypy session

You receive:
session params: bool autheticated, string user -- sAMAccountName, string user_cn -- User's canonical name, list groups -- groups that has user as member AND that person's primary group (This is not obvious but primary group doesn't have named user as its member by ldap standards)

