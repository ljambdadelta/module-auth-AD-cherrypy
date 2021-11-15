from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, NTLM
import cherrypy
# Security is succeeded by LDAPS usage. If lib user don't use LDPAS, well, it's user's headache


class LDAP(object):
    def isAuthSuccessful(self,session):
      if session.get('authenticated') is None:
        session['authenticated'] = False
      return session.get('authenticated') is True
          
    def _setAuthSuccessful(self, session):
        session['authenticated']=True
    
    def _domainToDC(self,domain):
      # converts x.y.z domain address to dc=x,dc=y,dc=z notation
      splitted_domain=domain.split(".")
      dc=""
      for word in splitted_domain:
        dc = dc + "dc=" + word + ","
      return dc[:-1]


    def _connectToServer(self, sAMAccountName, pw, srv, domain):
        if not "ldaps" in srv:
          print("Please, consider to upgrade your server to use LDAPS. Sending passwords in plain text is usually bad idea")
        # And we are living with this bad idea. Needs to be checked.
        logon_username=str(sAMAccountName+"@"+domain)
        ser = Server(srv, use_ssl=True, get_info=ALL) 
        con = Connection(ser, user=logon_username, password=pw)
        try:
          con.bind()
        except:
          print(con.result)
          return None, False
        return con, True
    
    def _getUserCNbysAMAccount(self,con,sAMAccountName,domain):
        # Gives Canonical Name for our authenticated user by his sAMAccountName aka login
        con.search(search_base=self._domainToDC(domain),search_filter='(&(objectclass=person)(sAMAccountName={}))'.format(sAMAccountName),attributes=['cn',])
        return con.entries[0].entry_dn

    def _getPrimaryGroupCNbysAMAccount(self,con,sAMAccountName,domain):
        con.search(search_base=self._domainToDC(domain),search_filter='(&(objectclass=person)(sAMAccountName={}))'.format(sAMAccountName),attributes=['primaryGroupID','objectSid'])
        userPrimaryGroupRID=str(con.entries[0].entry_attributes_as_dict['primaryGroupID'][0])
        userSID=con.entries[0].entry_attributes_as_dict['objectSid'][0]
        userPrimaryGroupSID='-'.join(userSID.split('-')[:-1])+'-'+userPrimaryGroupRID
        con.search(search_base=self._domainToDC(domain),search_filter='(&(objectclass=group)(objectSid={}))'.format(userPrimaryGroupSID))
        return con.response[0]['dn'].split(",")[0][3:]
         

    def _getGroupsCNListbyUserCN(self,con,domain,usr_cn):
        # Frankly speaking, you can take user's sAMAccount's attribute 'memberOf' but in the moment of creation i missed this attribute 
        # But it is working and the server there this module was designed for is not-so-highload so i just let it be as is
        # Gives CN list for every group this user is member of
        con.search(search_base=self._domainToDC(domain), search_filter='(&(objectclass=group)(member={}))'.format(usr_cn),)
        groups_dn_there_usr_has_membership=[entry['dn'] for entry in con.response if 'dn' in entry]
        groups_cn_there_usr_has_membership=[entry.split(",")[0][3:] for entry in groups_dn_there_usr_has_membership]
        return groups_cn_there_usr_has_membership

    def _setSessionUserdata(self,con,sAMAccountName,domain,session):
        usr_cn=self._getUserCNbysAMAccount(con=con,sAMAccountName=sAMAccountName,domain=domain)
        groups_cn=self._getGroupsCNListbyUserCN(con=con,domain=domain,usr_cn=usr_cn)
        primary_gr_cn=self._getPrimaryGroupCNbysAMAccount(con=con,sAMAccountName=sAMAccountName,domain=domain)
        groups_cn.append(primary_gr_cn)
        session['user']=sAMAccountName
        session['user_cn']=usr_cn
        session['groups']=groups_cn

    def auth(self, sAMAccountName, pw, srv, domain, session):
        if self.isAuthSuccessful(session):
          return "Successful"
          # Till i find why auth module called two times (and one -- with defaults) it has to be so. Sad story!
          # Well, it is not so sad -- if we consider that we had already authenticated desired person
          # But ye, that is still bad that I don't know why we are happining to execute again
          # Negative side: prev page is lost
        con,connected=self._connectToServer(sAMAccountName, pw, srv, domain)
        if not connected:
          return "Unsuccessful"
        self._setAuthSuccessful(session)
        self._setSessionUserdata(con=con,sAMAccountName=sAMAccountName,domain=domain,session=session)        
        return "Successful"

    def deauth(session):
        session['authenticated'] = False
        session['user'] = None 
        session['groups'] = None 
        session['user_cn'] = None
    
    def __init__(self):
        print("Authentication module object has been created")
