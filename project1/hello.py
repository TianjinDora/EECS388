from pymd5 import md5, padding
import httplib, urlparse, sys, urllib

m = "Use HMAC, not hashes"
h = md5()
h.update(m)
print h.hexdigest()
print len(m)
print len(padding(len(m)*8))
h = md5(state="3ecc68efa1871751ea9b0b1a5b25004d".decode("hex"), count=512)
x = "Good advice"
h.update(x)
print h.hexdigest()

h = md5()
h.update(m + padding(len(m)*8) + x)
print h.hexdigest()