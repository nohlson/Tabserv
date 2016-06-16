import ldap
import sys
import math
import xml.etree.ElementTree as ET
import requests
import re
import dateutil.parser
from dateutil.tz import tzlocal
import datetime
import traceback
import yaml
import getopt
import os
 

from requests.packages.urllib3.fields import RequestField
from requests.packages.urllib3.filepost import encode_multipart_formdata
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)


xmlns = {'t': 'http://tableau.com/api'}

###user and group class

class User:
    def __init__(self, username, user_id = None):
        self.username = username
        if user_id is None:
            self.user_id = None
        else:
            self.user_id = user_id
        self.memberOf = []
class Group:
    def __init__(self, groupname, group_id = None, members = None):
        self.groupname = groupname
        if group_id is None:
            self.group_id = None
        else:
            self.group_id = group_id
        if members is None:
            self.members = []
        else:
            self.members = members

####
# Functions for constructing HTTP multi-part requests and dealing with errors
####


def _make_multipart(parts):
    """
    Creates one "chunk" for a multi-part upload.

    'parts' is a dictionary that provides key-value pairs of the format name: (filename, body, content_type).

    Returns the post body and the content type string.

    For more information, see this post:
        http://stackoverflow.com/questions/26299889/how-to-post-multipart-list-of-json-xml-files-using-python-requests
    """

    mime_multipart_parts = []

    for name, (filename, blob, content_type) in parts.items():
        multipart_part = RequestField(name=name, data=blob, filename=filename)
        multipart_part.make_multipart(content_type=content_type)
        mime_multipart_parts.append(multipart_part)

    post_body, content_type = encode_multipart_formdata(mime_multipart_parts)
    content_type = ''.join(('multipart/mixed',) + content_type.partition(';')[1:])
    return post_body, content_type


def _handle_error(server_response):
    """
    Parses an error response for the error subcode and detail message
    and then displays them.
    
    Returns the error code and error message.
    """
    print("An error occurred")
    xml_response = ET.fromstring(_encode_for_display(server_response.text))
    error_code = xml_response.find('t:error', namespaces=xmlns).attrib.get('code')
    error_detail = xml_response.find('.//t:detail', namespaces=xmlns).text
    print("\tError code: " + str(error_code))
    print("\tError detail: " + str(error_detail))
    return error_code, error_detail


def _encode_for_display(text):
    """
    Encodes strings so they can display as ASCII in a Windows terminal window.
    This function also encodes strings for processing by xml.etree.ElementTree functions. 
    
    Returns an ASCII-encoded version of the text. Unicode characters are converted to ASCII placeholders (for example, "?").
    """
    return text.encode('ascii', errors="backslashreplace").decode('utf-8')

####
# Functions for authentication (sign in and sign out)
####


def sign_in(name, password, site=""):
    """
    Signs in to the server specified in the global SERVER variable.

    'name'     is the name (not ID) of the user to sign in as.
               Note that most of the functions in this example require that the user
               have server administrator permissions.
    'password' is the password for the user.
    'site'     is the ID (as a string) of the site on the server to sign in to. The
               default is "", which signs in to the default site.

    Returns the authentication token and the site ID.
    """
    url = SERVER + "/api/2.1/auth/signin"

    # Builds the request
    xml_payload_for_request = ET.Element('tsRequest')
    credentials_element = ET.SubElement(xml_payload_for_request, 'credentials', name=name, password=password)
    site_element = ET.SubElement(credentials_element, 'site', contentUrl=site)
    xml_payload_for_request = ET.tostring(xml_payload_for_request)

    # Makes the request to Tableau Server
    try:
        server_response = requests.post(url, data=xml_payload_for_request, verify=CERT_PATH)
    except requests.exceptions.ConnectionError:
        traceback.print_exc(file=sys.stdout)
        print("Unexpected Error: {0} Check Tableau Server host settings in config.".format(sys.exc_info()[0]))
        sys.exit(1)
    if server_response.status_code != 200:
        print(server_response.text)
        print("Check Tableau Server login/host settings in config.")
        sys.exit(1)
    # Reads and parses the response
    xml_response = ET.fromstring(_encode_for_display(server_response.text))
    
    # Gets the token and site ID
    token = xml_response.find('t:credentials', namespaces=xmlns).attrib.get('token')
    site_id = xml_response.find('.//t:site', namespaces=xmlns).attrib.get('id')
    user_id = xml_response.find('.//t:user', namespaces=xmlns).attrib.get('id')
    return token, site_id, user_id

def sign_out():
    """
    Destroys the active session
    """
    global TOKEN
    url = SERVER + "/api/2.1/auth/signout"
    server_response = requests.post(url, headers={'x-tableau-auth': TOKEN}, verify=CERT_PATH)
    TOKEN = None
    return

## Routines for synchronizing LDAP users and Groups with Tableau server

def create_user(name):
    url = SERVER + "/api/2.1/sites/{0}/users".format(SITE_ID)
    xml_payload_for_request = ET.Element('tsRequest')
    user = ET.SubElement(xml_payload_for_request, 'user', name=name, siteRole="Unlicensed")
    xml_payload_for_request = ET.tostring(xml_payload_for_request)
    print(xml_payload_for_request)
    server_response = requests.post(url, data=xml_payload_for_request, headers={'x-tableau-auth': TOKEN}, verify=CERT_PATH)

    # Checks HTTP status code. If the code is anything _except_ success (here, 201),
    # the code reads the <error> block from the response. The error code
    # in the block indicates the specific issue. The documentation for each method
    # provides a list of error codes that might be returned for that method.
    if server_response.status_code != 201:
        error, detail = _handle_error(server_response)
    xml_response = ET.fromstring(_encode_for_display(server_response.text))
    return xml_response.find('t:user', namespaces=xmlns)

def remove_user(user_id):
    url = SERVER + "/api/2.1/sites/{0}/users/{1}".format(SITE_ID, user_id)
    server_response = requests.delete(url, headers={'x-tableau-auth': TOKEN}, verify=CERT_PATH)

    # Checks HTTP status code. If the code is anything _except_ success (here, 201),
    # the code reads the <error> block from the response. The error code
    # in the block indicates the specific issue. The documentation for each method
    # provides a list of error codes that might be returned for that method.
    if server_response.status_code != 204:
        error, detail = _handle_error(server_response)
        return False
        
    return True

def remove_group(group_id):
    url = SERVER + "/api/2.1/sites/{0}/groups/{1}".format(SITE_ID, group_id)
    server_response = requests.delete(url, headers={'x-tableau-auth': TOKEN}, verify=CERT_PATH)

    # Checks HTTP status code. If the code is anything _except_ success (here, 201),
    # the code reads the <error> block from the response. The error code
    # in the block indicates the specific issue. The documentation for each method
    # provides a list of error codes that might be returned for that method.
    if server_response.status_code != 204:
        error, detail = _handle_error(server_response)
        return False
        
    return True

def create_group(name):
    """
    Creates a group on Tableau Server (local, not Active Directory).
    If the group already exists, the function finds the ID of the
    specified group.

    Note: This function illustrates how to check for error codes
    in the response. The pattern shown here can be used in other
    functions.

    'name'  is the name of the group tp create.

    Returns a <group> element with information about the specified group.
    """
    url = SERVER + "/api/2.1/sites/{0}/groups".format(SITE_ID)
    xml_payload_for_request = ET.Element('tsRequest')
    group = ET.SubElement(xml_payload_for_request, 'group', name=name)
    xml_payload_for_request = ET.tostring(xml_payload_for_request)
    server_response = requests.post(url, data=xml_payload_for_request, headers={'x-tableau-auth': TOKEN}, verify=CERT_PATH)

    # Checks HTTP status code. If the code is anything _except_ success (here, 201),
    # the code reads the <error> block from the response. The error code
    # in the block indicates the specific issue. The documentation for each method
    # provides a list of error codes that might be returned for that method.
    if server_response.status_code != 201:
        error, detail = _handle_error(server_response)
        # 409009 is the error code when the group already exists.
        if error == "409009":
            # A group with the specified name already exists. Therefore, gets a list
            # of existing groups and finds the ID of the group with the specified name.
            groups = query_groups()
            for group in groups:
                if group.get('name') == name:
                    return group
            else:
                print(detail)
                sys.exit(1) # Exit the program altogether
    xml_response = ET.fromstring(_encode_for_display(server_response.text))
    return xml_response.find('t:group', namespaces=xmlns)


def add_user_to_group(user_id, group_id):
    url = SERVER + "/api/2.1/sites/{0}/groups/{1}/users".format(SITE_ID, group_id)
    xml_payload_for_request = ET.Element('tsRequest')
    user = ET.SubElement(xml_payload_for_request, 'user', id=user_id)
    xml_payload_for_request = ET.tostring(xml_payload_for_request)
    server_response = requests.post(url, data=xml_payload_for_request, headers={'x-tableau-auth': TOKEN}, verify=CERT_PATH)

    # Checks HTTP status code. If the code is anything _except_ success (here, 201),
    # the code reads the <error> block from the response. The error code
    # in the block indicates the specific issue. The documentation for each method
    # provides a list of error codes that might be returned for that method.
    if server_response.status_code != 200:
        error, detail = _handle_error(server_response)
        # 409009 is the error code when the group already exists.
        if error == "409011":
            # A group with the specified name already exists. Therefore, gets a list
            # of existing groups and finds the ID of the group with the specified name.
            groups = query_groups()
            for group in groups:
                if group.get('name') == name:
                    return group
            else:
                print(detail)
                sys.exit(1) # Exit the program altogether
    xml_response = ET.fromstring(_encode_for_display(server_response.text))
    return xml_response.find('t:user', namespaces=xmlns)

def remove_user_from_group(user_id, group_id):
    url = SERVER + "/api/2.1/sites/{0}/groups/{1}/users/{2}".format(SITE_ID, group_id, user_id)
    server_response = requests.delete(url, headers={'x-tableau-auth': TOKEN}, verify=CERT_PATH)

    # Checks HTTP status code. If the code is anything _except_ success (here, 201),
    # the code reads the <error> block from the response. The error code
    # in the block indicates the specific issue. The documentation for each method
    # provides a list of error codes that might be returned for that method.
    if server_response.status_code != 204:
        error, detail = _handle_error(server_response)
        return False
        
    return True


##functions for querying groups and users

def query_groups():
    """
    Returns a list of groups on the site (a list of <group> elements).
    
    The function paginates over the results (if required) using a page size of 100.
    """
    pageNum, pageSize = 1, 100
    url = SERVER + "/api/2.1/sites/{0}/groups".format(SITE_ID)
    paged_url = url + "?pageSize={}&pageNumber={}".format(pageSize, pageNum)
    server_response = requests.get(paged_url, headers={"x-tableau-auth": TOKEN}, verify=CERT_PATH)
    if server_response.status_code != 200:
        print(_encode_for_display(server_response.text))
        sys.exit(1)
    xml_response = ET.fromstring(_encode_for_display(server_response.text))
    total_count_of_groups = int(xml_response.find('t:pagination', namespaces=xmlns).attrib.get('totalAvailable'))
    if total_count_of_groups > pageSize:
        groups = []  # A list to hold the groups returned from the server
        groups.extend(xml_response.findall('.//t:group', namespaces=xmlns))
        number_of_pages = int(math.ceil(total_count_of_groups / pageSize))
        # Starts from page 2 because page 1 has already been returned
        for page in range(2, number_of_pages + 1):
            paged_url = url + "?pageSize={}&pageNumber={}".format(pageSize, page)
            server_response = requests.get(paged_url, headers={"x-tableau-auth": TOKEN}, verify=CERT_PATH)
            if server_response.status_code != 200:
                print(_encode_for_display(server_response.text))
                sys.exit(1)
            groups_from_page = ET.fromstring(_encode_for_display(server_response.text)).findall('.//t:group', namespaces=xmlns)
            # Adds the new page of groups to the list
            groups.extend(groups_from_page)
    else:
        groups = xml_response.findall('.//t:group', namespaces=xmlns)
    return groups

def query_users():
    """
    Returns a list of users on the site (a list of <user> elements).

    The function paginates over the results (if required) using a page size of 100.
    """
    pageNum, pageSize = 1, 100
    url = SERVER + "/api/2.1/sites/{0}/users".format(SITE_ID)
    paged_url = url + "?pageSize={}&pageNumber={}".format(pageSize, pageNum)
    server_response = requests.get(paged_url, headers={"x-tableau-auth": TOKEN}, verify=CERT_PATH)
    if server_response.status_code != 200:
        print(_encode_for_display(server_response.text))
        sys.exit(1)
    xml_response = ET.fromstring(_encode_for_display(server_response.text))
    total_count_of_users = int(xml_response.find('t:pagination', namespaces=xmlns).attrib.get('totalAvailable'))
    if total_count_of_users > pageSize:
        users = []  # A list to hold the users returned from the server
        users.extend(xml_response.findall('.//t:user', namespaces=xmlns))
        number_of_pages = int(math.ceil(total_count_of_users / pageSize))
        # Starts from page 2 because page 1 has already been returned
        for page in range(2, number_of_pages + 1):
            paged_url = url + "?pageSize={}&pageNumber={}".format(pageSize, page)
            server_response = requests.get(paged_url, headers={"x-tableau-auth": TOKEN}, verify=CERT_PATH)
            if server_response.status_code != 200:
                print(_encode_for_display(server_response.text))
                sys.exit(1)
            users_from_page = ET.fromstring(_encode_for_display(server_response.text)).findall('.//t:user', namespaces=xmlns)
            # Adds the new page of users to the list
            users.extend(users_from_page)
    else:
        users = xml_response.findall('.//t:user', namespaces=xmlns)
    return users

def get_users_in_group(group_id):
    """
    Returns a list of users on the site (a list of <user> elements).

    The function paginates over the results (if required) using a page size of 100.
    """
    pageNum, pageSize = 1, 100
    url = SERVER + "/api/2.1/sites/{0}/groups/{1}/users".format(SITE_ID, group_id)
    paged_url = url + "?pageSize={}&pageNumber={}".format(pageSize, pageNum)
    server_response = requests.get(paged_url, headers={"x-tableau-auth": TOKEN}, verify=CERT_PATH)
    if server_response.status_code != 200:
        print(_encode_for_display(server_response.text))
        sys.exit(1)
    xml_response = ET.fromstring(_encode_for_display(server_response.text))
    total_count_of_users = int(xml_response.find('t:pagination', namespaces=xmlns).attrib.get('totalAvailable'))
    if total_count_of_users > pageSize:
        users = []  # A list to hold the users returned from the server
        users.extend(xml_response.findall('.//t:user', namespaces=xmlns))
        number_of_pages = int(math.ceil(total_count_of_users / pageSize))
        # Starts from page 2 because page 1 has already been returned
        for page in range(2, number_of_pages + 1):
            paged_url = url + "?pageSize={}&pageNumber={}".format(pageSize, page)
            server_response = requests.get(paged_url, headers={"x-tableau-auth": TOKEN}, verify=CERT_PATH)
            if server_response.status_code != 200:
                print(_encode_for_display(server_response.text))
                sys.exit(1)
            users_from_page = ET.fromstring(_encode_for_display(server_response.text)).findall('.//t:user', namespaces=xmlns)
            # Adds the new page of users to the list
            users.extend(users_from_page)
    else:
        users = xml_response.findall('.//t:user', namespaces=xmlns)
    return users

## LDAP routines
def getLDAPUser(username):

    l = ldap.initialize(LDAP_HOST)
    l.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
    l.set_option( ldap.OPT_X_TLS_DEMAND, True )
    searchFilter = "(&(uid={0})(objectClass={1}))".format(username, USER_OBJECT_CLASS)
    #this will scope the entire subtree under UserUnits
    searchScope = ldap.SCOPE_SUBTREE
    #Bind to the server
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(LDAP_BIND_DN, LDAP_PASSWORD)
    except ldap.LDAPError, e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print e.message['desc']
        else: 
            print e
            sys.exit(1)
    try:
        ldap_result_id = l.search(LDAP_USERS_BASE_DN, searchScope, searchFilter, None)
        result_set = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
    except ldap.LDAPError, e:
        print e
        sys.exit(1)
    l.unbind_s()
    return result_set[0][0]




def getAllLDAPUsers():

    l = ldap.initialize(LDAP_HOST)
    l.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
    l.set_option( ldap.OPT_X_TLS_DEMAND, True )
    searchFilter = "(&(cn=*)(objectClass={0}))".format(USER_OBJECT_CLASS)
    #this will scope the entire subtree under UserUnits
    searchScope = ldap.SCOPE_SUBTREE
    #Bind to the server
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(LDAP_BIND_DN, LDAP_PASSWORD)
    except ldap.LDAPError, e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print e.message['desc']
        else: 
            print e
            sys.exit(1)
    try:
        ldap_result_id = l.search(LDAP_USERS_BASE_DN, searchScope, searchFilter, None)
        result_set = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
    except ldap.LDAPError, e:
        print e
        sys.exit(1)
    l.unbind_s()
    return result_set

def getAllLDAPGroups():
    l = ldap.initialize(LDAP_HOST)
    l.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
    l.set_option( ldap.OPT_X_TLS_DEMAND, True )
    searchFilter = "(&(cn=*)(objectClass=posixGroup))"
    #this will scope the entire subtree under UserUnits
    searchScope = ldap.SCOPE_SUBTREE
    #Bind to the server
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(LDAP_BIND_DN, LDAP_PASSWORD)
    except ldap.INVALID_CREDENTIALS:
        print 'Your LDAP username or password is incorrect'
        sys.exit(1)
    except ldap.LDAPError, e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print e.message['desc']
        else: 
            print e
            sys.exit(1)
    try:
        ldap_result_id = l.search(LDAP_GROUPS_BASE_DN, searchScope, searchFilter, None)
        result_set = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
    except ldap.LDAPError, e:
        print e
        sys.exit(1)
    l.unbind_s()
    return result_set

def getLDAPGroup(group_name):
    l = ldap.initialize(LDAP_HOST)
    l.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
    l.set_option( ldap.OPT_X_TLS_DEMAND, True )
    searchFilter = "(cn={0})".format(group_name)
    #this will scope the entire subtree under UserUnits
    searchScope = ldap.SCOPE_SUBTREE
    #Bind to the server
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(LDAP_BIND_DN, LDAP_PASSWORD)
    except ldap.INVALID_CREDENTIALS:
        print 'Your LDAP username or password is incorrect'
        sys.exit(1)
    except ldap.LDAPError, e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print e.message['desc']
        else: 
            print e
            sys.exit(1)
    try:
        ldap_result_id = l.search(LDAP_GROUPS_BASE_DN, searchScope, searchFilter, None)
        result_set = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
    except ldap.LDAPError, e:
        print e
        sys.exit(1)
    l.unbind_s()
    try:
        return result_set[0]
    except IndexError:
        traceback.print_exc(file=sys.stdout)
        print("Unexpected Error: {0} Could not find Group matching search criterea (check groupgroup name).".format(sys.exc_info()[0]))
        sys.exit(1)
    return None

#recursive algorithm for building up users in subclasses of a group, could be rewritten to use LDAP SUBTREE search calls
# add users from "group_name" group to the "parent_group" while adding all users to the "users" list
def getUsersInGroup(parent_group, group_name, users):
    user_objects_in_group = []
    temp_ldap_group = getLDAPGroup(group_name)
    users_in_group = temp_ldap_group[0][1].get('member')
    for groupuser in range(len(users_in_group)):
        if (users_in_group[groupuser][0:2] == "cn"):
            getUsersInGroup(parent_group, re.search("=(.*?),", users_in_group[groupuser]).group(1), users)
        else:
            current_username = re.search("=(.*?),", users_in_group[groupuser]).group(1)
            current_user_info = getLDAPUser(current_username)
            if current_user_info[1].get('krbPasswordExpiration') is not None:
                passwordExpiration = dateutil.parser.parse(current_user_info[1].get('krbPasswordExpiration')[0])
                timed = CURRENT_DATE_TIME - passwordExpiration
                if CHECK_PASSWORD_EXPIRY and timed.days > PASSWORD_EXPIRATION_LIMIT:
                    print("Discovered expired ({0} days) LDAP user: {1} in group: {2} for parent group {3}, {4} days".format(PASSWORD_EXPIRATION_LIMIT, current_username, group_name, parent_group.groupname, timed.days))
                else:
                    user_found_in_users = False
                    for alluse in range(len(users)):
                        if current_username == users[alluse].username:
                            users[alluse].memberOf.append(parent_group)
                            parent_group.members.append(users[alluse])
                            user_found_in_users = True
                            break
                    if not user_found_in_users:
                        temp_user = User(current_username)
                        temp_user.memberOf.append(parent_group)
                        parent_group.members.append(temp_user)
                        users.append(temp_user)
            else:
                print("Found none type in krbPasswordExpiration for LDAP user {0} in group {1} for parent group {2}".format(current_username, group_name, parent_group.groupname))
    return user_objects_in_group

## Calls recursive algorithm to build a group from groupname    
def buildGroup(group_name, users):
    temp_group = Group(group_name)
    temp_ldap_group = getLDAPGroup(group_name)
    getUsersInGroup(temp_group, temp_group.groupname, users)
    #check for duplicate users in list
    i = 0
    while i < len(temp_group.members):
        j = i
        while j < len(temp_group.members):
            if ((temp_group.members[i].username == temp_group.members[j].username) and (i != j)):
                temp_group.members.pop(j)
            else:
                j += 1
        i += 1

    return temp_group




    
def main():
    global SITE_ID
    global MY_USER_ID
    global TOKEN

    users = []
    groups = []

    if MODE == "groupgroup":
        ##pull groups from LDAP and populate group ob0jects
        tableaugroupsgroup = getLDAPGroup(LDAP_GROUP_GROUP)
        tableaugroupsgroupmembers = tableaugroupsgroup[0][1].get('member')
    
        try:
            ldaptableaugroups = []
            for member in tableaugroupsgroupmembers:
                ldaptableaugroups.append(re.search("=(.*?),", member).group(1))
            print("Groups:")
            for mem in ldaptableaugroups:
                print("    Member: {0}".format(mem))
        except TypeError:
            traceback.print_exc(file=sys.stdout)
            print("Unexpected Error: {0} Check LDAP groupsBaseDN or login user DN".format(sys.exc_info()[0]))
            sys.exit(1)
        
        #loop through all of the groups that were in the tableaugroups group
        for i in range(len(ldaptableaugroups)):
            temp_group = buildGroup(ldaptableaugroups[i], users)
            groups.append(temp_group)
    elif MODE == "all":
        #TODO: create all routine
        pass
    #sign into Tableau Server REST API
    print("Signing in")
    TOKEN, SITE_ID, MY_USER_ID = sign_in(USER, PASSWORD)
    print("Successfully logged in...\n")

    #retrieve list of Tableau users
    tab_users = query_users()

    #retreieve list of Tableau groups
    tab_groups = query_groups()


    ## create group objects for Tabserv groups
    tab_group_objects = []
    for i in range(len(tab_groups)):
        if tab_groups[i].get('name') != "All Users": #don't process all users. those tasks can be accomplished by doing a query on all Tableau Users
            temp_group = Group(tab_groups[i].get('name'), tab_groups[i].get('id'))
            temp_users_in_group = get_users_in_group(temp_group.group_id)
            for j in range(len(temp_users_in_group)):
                temp_group.members.append(User(temp_users_in_group[j].get('name'), temp_users_in_group[j].get('id')))
            tab_group_objects.append(temp_group)
    ## create User objects for Tabserv users
    tab_user_objects = []
    for i in range(len(tab_users)):
        temp_user = User(tab_users[i].get('name'), tab_users[i].get('id'))
        tab_user_objects.append(temp_user)


    for j in range(len(users)):
        if users[j].username == "nohlson":
            users[j].user_id = "hey"

    #debug purposes only:
    #####for debug purposes only#####
    print("\n")
    print("LDAP Users (Total: "+ str(len(users)) + "):")
    for u in users:
        print("Username: {0}, id: {1}".format(u.username, u.user_id))
    print("\n")

    print("LDAP Groups (Total: "+ str(len(groups)) + "):")
    for g in groups:
        print("Groupname: {0}, (Total: {1}):".format(g.groupname, len(g.members)))
        for m in g.members:
            print("    Username: {0}, id: {1}".format(m.username, m.user_id))
    print("Tableau Users (Total: "+ str(len(tab_user_objects)) + "):")
    for tu in tab_user_objects:
        print("Username: {0}, id:{1}".format(tu.username, tu.user_id))
    print("Tableau Groups (Total: "+str(len(tab_group_objects)) + "):")
    for tg in tab_group_objects:
        print("Groupname: {0} {1} (Total: {2}):".format(tg.groupname, tg.group_id, len(tg.members)))
        for tgm in tg.members:
            print("    Username: {0}, id: {1}".format(tgm.username, tgm.user_id))



    #    determine which groups/users exist on Tabserv and not in LDAP. Add those groups/users to deletion queue. If Tabserv group/
    #    users exist in LDAP then update their objects id 
    user_objects_to_be_deleted = []
    group_objects_to_be_deleted = []
    user_remove_indecies = []
    group_remove_indecies = []

    for i in range(len(tab_user_objects)):
        tab_user_found_in_ldap_users= False
        for j in range(len(users)):
            if (users[j].username == tab_user_objects[i].username):
                tab_user_found_in_ldap_users = True
                users[j].user_id = tab_user_objects[i].user_id
                break
        if not tab_user_found_in_ldap_users:
            if (tab_user_objects[i].username != "admin"): #do not add admin user to the deletion queue ever, even if there is no admin user in LDAP. WE NEED TO GET IN DER!
                user_objects_to_be_deleted.append(tab_user_objects[i])
                # user_remove_indecies.append(i)

    for i in range(len(tab_group_objects)):
        tab_group_found_in_ldap_groups = False
        for j in range(len(groups)):
            if (groups[j].groupname == tab_group_objects[i].groupname):
                tab_group_found_in_ldap_groups = True
                groups[j].group_id = tab_group_objects[i].group_id
                break
        if not tab_group_found_in_ldap_groups:
            if (tab_group_objects[i].groupname != "All Users"): #Do not delete group ALL users
                group_objects_to_be_deleted.append(tab_group_objects[i])
                # group_remove_indecies.append(i)

    # determine users and groups that exist in LDAP but don't exist in Tabserv
    users_to_be_added = []
    groups_to_be_added = []
    for i in range(len(users)):
        user_in_both = False
        for j in range(len(tab_users)):
            if (users[i].username == tab_users[j].get('name')):
                user_in_both = True
                break
        if not user_in_both:
            users_to_be_added.append(users[i])

    for i in range(len(groups)):
        group_in_both = False
        for j in range(len(tab_groups)):
            if (groups[i].groupname == tab_groups[j].get('name')):
                group_in_both = True
                break
        if not group_in_both:
            groups_to_be_added.append(groups[i])
    ##########################################################################

    users_add_to_groups = []
    for i in range(len(groups)):
        #first check to see if this group is a new group for Tabserv. if it is add all of its members to the add to group queue
        group_found_in_add_groups = False
        for b in range(len(groups_to_be_added)):
            if (groups[i].groupname == groups_to_be_added[b].groupname):
                group_found_in_add_groups = True
                break
        if group_found_in_add_groups:
            #add all users from group to add to group queue
            for y in range(len(groups[i].members)):
                users_add_to_groups.append({'user':groups[i].members[y], 'group':groups[i]})
        else:
            for j in range(len(tab_group_objects)):
                if (groups[i].groupname == tab_group_objects[j].groupname):
                    for k in range(len(groups[i].members)):
                        user_in_both_groups = False
                        for m in range(len(tab_group_objects[j].members)):
                            if (groups[i].members[k].username == tab_group_objects[j].members[m].username):
                                user_in_both_groups = True
                                break
                        if not user_in_both_groups:
                            users_add_to_groups.append({'user':groups[i].members[k], 'group':groups[i]})


    users_del_from_groups = []
    for i in range(len(tab_group_objects)):
        for j in range(len(groups)):
            if (tab_group_objects[i].groupname == groups[j].groupname):
                for k in range(len(tab_group_objects[i].members)):
                    found_in_both_groups = False
                    for m in range(len(groups[j].members)):
                        if (tab_group_objects[i].members[k].username == groups[j].members[m].username):
                            found_in_both_groups = True
                            break
                    if not found_in_both_groups:
                        found_in_delete_list = False
                        for n in range(len(user_objects_to_be_deleted)):
                            if (user_objects_to_be_deleted[n] == tab_group_objects[i].members[k].user_id):
                                found_in_delete_list = True
                                break
                        if not found_in_delete_list:
                            users_del_from_groups.append({'user':tab_group_objects[i].members[k], 'group':tab_group_objects[i]})
    

    print("\nTABSYNC Tasks:\n")

    print("Users to be deleted from Tableau Server:")
    for delus in user_objects_to_be_deleted:
        print("    {0}, {1}".format(delus.username, delus.user_id))
    print("Groups to be deleted from Tableau Server:")
    for delgro in group_objects_to_be_deleted:
        print("    {0}, {1}".format(delgro.groupname, delgro.group_id))
    print("Users to be added to Tableau Server:")
    for adus in users_to_be_added:
        print("    {0}".format(adus.username))
    print("Groups to be added to Tableau Server:")
    for adgr in groups_to_be_added:
        print("    {0}".format(adgr.groupname))
    print("Users to be added to groups:")
    for uadd in users_add_to_groups:
        print("    {0} with ID {1} will be added to group {2} with ID {3}".format(uadd.get('user').username, uadd.get('user').user_id, uadd.get('group').groupname, uadd.get('group').group_id))

    print("Users to be deleted from groups:")
    for udel in users_del_from_groups:
        print("    {0} with ID {1} will be deleted from group {2} with ID {3}".format(udel.get('user').username, udel.get('user').user_id, udel.get('group').groupname, udel.get('group').group_id))


    print("Execute tasks:\n")


    ###EXECUTE TASKS######
    ##Add Users
    print("Add Users:")
    for i in range(len(users_to_be_added)):
        print("    Adding user: {0}".format(users_to_be_added[i].username))
        user_return = create_user(users_to_be_added[i].username)
        user_return_id = user_return.get('id')
        users_to_be_added[i].user_id = user_return_id
        print("    Success! User {0} was added with ID: {1}".format(user_return.get('name'), user_return_id))

    ##Del Users
    print("Remove Users:")
    for i in range(len(user_objects_to_be_deleted)):
        print("    Removing user: {0} with ID: {1}".format(user_objects_to_be_deleted[i].username, user_objects_to_be_deleted[i].user_id))
        remove_user(user_objects_to_be_deleted[i].user_id)
        print("    User deleted.")


    ##Add Groups
    print("Add Groups:")
    for i in range(len(groups_to_be_added)):
        print("    Adding group: {0}".format(groups_to_be_added[i].groupname))
        group_return = create_group(groups_to_be_added[i].groupname)
        group_return_id = group_return.get('id')
        groups_to_be_added[i].group_id = group_return_id
        print("    Success! Group {0} was added with ID: {1}".format(group_return.get('name'), group_return_id))


    ##Del Groups
    print("Remove Groups:")
    for i in range(len(group_objects_to_be_deleted)):
        print("    Removing group: {0} with ID: {1}".format(group_objects_to_be_deleted[i].groupname, group_objects_to_be_deleted[i].group_id))
        remove_group(group_objects_to_be_deleted[i].group_id)
        print("    Group deleted.")


    ##Add users to Groups
    print("Add users to groups:")
    for i in range(len(users_add_to_groups)):
        t_username = users_add_to_groups[i].get('user').username
        t_user_id = users_add_to_groups[i].get('user').user_id
        t_groupname = users_add_to_groups[i].get('group').groupname
        t_group_id = users_add_to_groups[i].get('group').group_id
        print("    Adding user {0} with ID: {1} to group {2} with ID {3}".format(t_username, t_user_id, t_groupname, t_group_id))
        user_return = add_user_to_group(t_user_id, t_group_id)
        user_return_id = user_return.get('id')
        print("    Success! User {0} was added to {1}".format(user_return.get('name'), t_groupname))

    ##Del users from Groups
    print("Remove Users from Groups:")
    for i in range(len(users_del_from_groups)):
        t_username = users_del_from_groups[i].get('user').username
        t_user_id = users_del_from_groups[i].get('user').user_id
        t_groupname = users_del_from_groups[i].get('group').groupname
        t_group_id = users_del_from_groups[i].get('group').group_id
        print("    Deleting user {0} with ID: {1} from group {2} with ID {3}".format(t_username, t_user_id, t_groupname, t_group_id))
        remove_user_from_group(t_user_id, t_group_id)
        print("    Deleted user from group.")



def printUsage():
    print("Tabsync usage:\n    python tabsync.py\nModes:\n    -g:    group group MODE(default)\n    -a:    all mode\n\nSee README for more information")






if __name__ == '__main__':
    arguments={}
    configfile = "config/config.yml"
    MODE = "groupgroup"
    try:
        opts, args = getopt.getopt(sys.argv, "hd:c:")
        for opt, arg in opts:
            if opt == '-c':
                configfile = arg
            elif opt == '-g':
                MODE = 'groupgroup'
            elif opt == '-a':
                MODE = 'all'
        
        with open(configfile, 'r') as ymlfile:
            config = yaml.load(ymlfile)
    
        SERVER = config['tableau']['server'] # Set to the server URL without a trailing slash (/).
        USER = config['tableau']['user']
        PASSWORD = config['tableau']['password']
        CERT_PATH = config['tableau']['certpath']
        LDAP_HOST = config['ldap']['host']
        LDAP_BIND_DN = config['ldap']['bindDN']
        LDAP_PASSWORD = config['ldap']['password']
        LDAP_GROUPS_BASE_DN = config['ldap']['groupsbaseDN']
        LDAP_USERS_BASE_DN = config['ldap']['usersbaseDN']
        USER_OBJECT_CLASS = config['ldap']['userobjectclass']
        LDAP_GROUP_GROUP = config['ldap']['groupgroup']
        CURRENT_DATE_TIME = datetime.datetime.now(tzlocal())
        CHECK_PASSWORD_EXPIRY = config['ldap']['checkforpasswordexpiry']
        PASSWORD_EXPIRATION_LIMIT = int(config['ldap']['passwordExpirationLimit'])
    except KeyError:
        traceback.print_exc(file=sys.stdout)
        print("Unexpected Error: {0} Incorrect or incomplete config file.".format(sys.exc_info()[0]))
        sys.exit(1)
    except getopt.GetoptError:
        print("Unexpected Error: {0} Incorrect arguments")
        printUsage()
        sys.exit(1)
    main()


