##################################################################################################
# Copyright (c) 2012 Brett Dixon
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in 
# the Software without restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
# Software, and to permit persons to whom the Software is furnished to do so, 
# subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all 
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION 
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
##################################################################################################


import ldap
from django.conf import settings
from django.contrib.auth.models import User

class LDAPAuthBackend(object):
    """
    Authenticate against the settings ADMIN_LOGIN and ADMIN_PASSWORD.

    Use the login name, and a hash of the password. For example:

    ADMIN_LOGIN = 'admin'
    ADMIN_PASSWORD = 'sha1$4e987$afbcf42e21bd417fb71db8c66b321e9fc33051de'
    """

    supports_inactive_user = False

    def authenticate(self, username=None, password=None):
        
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 30)
        ldap.set_option(ldap.OPT_REFERRALS, 0)  # Required for Active Directory
        ldap.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)

        try:
            try:
                ld = ldap.initialize(settings.LDAP_HOST)
                ld.simple_bind_s(username, password)
            except ldap.LDAPError, e:
                if username != "admin":
                    print ("ldap error", e)
                    #ld.unbind()
                    return None

            uname = username.split('@')[0]
            user = User.objects.get(username=uname)
        except User.DoesNotExist:
            # create a new user.  we are using this for the user repository only
            # and not authentication, since that's handled by AD, so we will set the same 
            # password for everyone. 

            searchFilter = "(&(objectCategory=person)(objectClass=user)(userPrincipalName=" + username + "))"
            results = ld.search_st(base=settings.LDAP_BASE_DN,scope=ldap.SCOPE_SUBTREE,filterstr=searchFilter,timeout=30)
            
            first_name = results[0][1]['givenName'][0]
            last_name = results[0][1]['sn'][0]
            email = results[0][1]['userPrincipalName'][0]
            # saving user
            user = User(username=uname, password='rad')
            user.is_staff = False
            user.is_superuser = False
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.save()

        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None