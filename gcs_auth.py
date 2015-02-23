#!/usr/bin/python
# Copyright (C) 2011 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This code is not supported by Google

import sys
import getopt
import datetime
import time
import base64
import sys
import logging
import urllib,urllib2
from urllib2 import URLError, HTTPError
import json

from OpenSSL import crypto

"""
This script acquires an oauth2 bearer access_token use with authenticated GCS 
ShoppingAPI and ContentAPI requests.  GCS customers should use one of the 
libraries shown below to get the token in a production setting.  This script is 
provided to demonstrate the encryption and structure of getting an oauth2 bearer
 tokens. Ensure the computer this script is run on is synced with a NTP server.
 
 apt-get install python-openssl 
 
 install python crypto to
 /usr/local/lib/python2.6/dist-packages/Crypto

REFERENCE :
https://developers.google.com/commerce-search/docs/shopping_auth
https://developers.google.com/accounts/docs/OAuth2ServiceAccount
http://code.google.com/p/google-api-python-client/downloads/list
code.google.com/p/google-api-python-client/source/browse/oauth2client/crypt.py
http://packages.python.org/pyOpenSSL/
https://www.dlitz.net/software/pycrypto/

USAGE: 
    python gcs_auth.py --client_id= --key=

- arguments
  client_id: 'email' for the service account
  key: private key for the service account
  see
  https://developers.google.com/console/help/#service_accounts
  http://code.google.com/p/gcs-admin-toolkit/wiki/GCSAuthentication
  
- The output is an access_token that should be used in a GCS Search API call.
"""

class gcs_auth(object):
  
  SCOPES ='https://www.googleapis.com/auth/shoppingapi'
  SCOPES = SCOPES + ' https://www.googleapis.com/auth/structuredcontent'
  
  def __init__(self, client_id, key):
        
    try:
      f = file(key, 'rb')
      key = f.read()
    except IOError,e:
       self.log('Unable to open private key file: ' + key,logging.ERROR)
       sys.exit()
    f.close()
    pkey = crypto.load_pkcs12(key, 'notasecret').get_privatekey()
    
    jwt_header = '{"alg":"RS256","typ":"JWT"}'
    
    iss = client_id
    now = int(time.time())
    exptime = now + 3600
    claim =('{"iss":"%s",'
            '"scope":"%s",'
            '"aud":"https://accounts.google.com/o/oauth2/token",'
            '"exp":%s,'
            '"iat":%s}') %(iss,self.SCOPES,exptime,now)    

    jwt = self._urlsafe_b64encode(jwt_header) + '.' + \
          self._urlsafe_b64encode(unicode(claim, 'utf-8'))

    e = crypto.sign(pkey, jwt, 'sha256')
    assertion = jwt + '.' + self._urlsafe_b64encode(e)

    #self.log('header.claim: ' + jwt_header + '.' + claim, logging.DEBUG)
    #self.log('b64(header).b64(claim).b64(sign(b64(header).b64(claim))): ' + 
    #         assertion, logging.DEBUG)

    url = 'https://accounts.google.com/o/oauth2/token'
    data = {'grant_type' : 'assertion',
            'assertion_type' : 'http://oauth.net/grant_type/jwt/1.0/bearer',
            'assertion' : assertion }
    headers = {"Content-type": "application/x-www-form-urlencoded"}
     
    data = urllib.urlencode(data)
    req = urllib2.Request(url, data, headers)

    try:
      resp = urllib2.urlopen(req).read()
      parsed = json.loads(resp)
      self.access_token = parsed.get('access_token')
      self.log('access_token: ' + self.access_token,  logging.INFO)
    except HTTPError, e:
      self.log('Error code: ' + str(e.code),logging.ERROR)
      self.log(e.read(),logging.ERROR)
    except URLError, e:
      self.log( 'Reason: ' + str(e.reason),logging.ERROR)
      self.log(e.read(),logging.ERROR)      
      sys.exit(1)
      
  def read_token(self):
    return self.access_token
   
  # taken from /oauth2client/crypt.py   
  def _urlsafe_b64encode(self,raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).rstrip('=')
   
  def _urlsafe_b64decode(self,b64string):
    # Guard against unicode strings, which base64 can't handle.
    b64string = b64string.encode('ascii')
    padded = b64string + '=' * (4 - len(b64string) % 4)
    return base64.urlsafe_b64decode(padded)
      
#  http://code.google.com/p/google-api-python-client/
#  def googleAPIClient(self, client_id, key):
#    from oauth2client.client import SignedJwtAssertionCredentials
#    f = file(key, 'rb')
#    key = f.read()
#    f.close()
#    credentials = SignedJwtAssertionCredentials(
#        client_id,
#        key,
#        scope='https://www.googleapis.com/auth/shoppingapi')
#    http = httplib2.Http()
#    http = credentials.authorize(http)
#    credentials.refresh(http)
#    print credentials.access_token


  def log(self,msg, loglevel):
    #LOG_FILENAME = 'gcsoauth.log'
    #logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO)
    m = ('[%s] %s') % (datetime.datetime.now(), msg)
    print m
    if (loglevel == logging.DEBUG):
      logging.debug(m)   
    else:
      logging.info(m)
               
if __name__ == '__main__':
  key = None
  client_id = None

  try:
    opts, args = getopt.getopt(sys.argv[1:], None, ["client_id=","key="])
  except getopt.GetoptError:
    print 'Please specify --client_id= --key='
    sys.exit(1)

  for opt, arg in opts:
    if opt == "--client_id":
      client_id = arg    
    if opt == "--key":
      key = arg
      
  if (key is not None and client_id is not None):
    gcs_auth(client_id,key)
