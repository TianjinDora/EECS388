from pymd5 import md5, padding
import httplib, urlparse, sys, urllib
url = "http://eecs388.org/project1/api?token=b301afea7dd96db3066e631741446ca1&user=admin&command1=ListFiles&command2=NoOp"
message = "&user=admin&command1=ListFiles&command2=NoOp"
append = "&command3=DeleteAllFiles"
# Your code to modify url goes here

parsedUrl = urlparse.urlparse(url)
#get old token
query = parsedUrl.query
print query
queryDictionary = urlparse.parse_qs(query)
oldToken = queryDictionary["token"][0]
print "old token = "  + " " + oldToken
#calculate new token
h = md5(state=oldToken.decode("hex"), count=512) 
h.update(urllib.quote(append))
newToken = h.hexdigest()

print "new token = " + " " + newToken

newQuery = "token=" + newToken + message + append
print newQuery

conn = httplib.HTTPConnection(parsedUrl.hostname)
conn.request("GET", parsedUrl.path + "?" + newQuery)

print conn.getresponse().read()


