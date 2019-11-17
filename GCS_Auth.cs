/*#
# Copyright 2012 Google Inc. All Rights Reserved.
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
#
# This code is not supported by Google
#
*/
/**
* This script acquires an oauth2 access_token for use with authenticated GCS 
* ShoppingAPI and ContentAPI requests.  GCS customers should use one of the 
* libraries shown below to get the token in a production setting.  This script 
* is provided to demonstrate the encryption and structure of getting an oauth2 
* bearer tokens.  Ensure the computer this script is run on is synced with a 
* NTP server.
* REFERENCE :
* https://developers.google.com/console/help/#service_accounts
* https://developers.google.com/commerce-search/docs/shopping_auth
* https://developers.google.com/accounts/docs/OAuth2ServiceAccount
* http://www.dotnetopenauth.net/
* http://msdn.microsoft.com/en-us/library/windows/desktop/bb931357(v=vs.85).aspx
*
*   c:\WINDOWS\Microsoft.NET\Framework\v4.0.30319\csc.exe /main:GCS.JWT *.cs
*
*   JWT.exe -client_id= -key= 
*   
*     client_id=<clientID Service account  'email'>    
*     key = <private key for the service account> (e.g. c:\\privkey.p12)
*/
 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Diagnostics;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security;
using System.Net;
using System.IO;
namespace GCS
{
    class JWT
    {
        String lauth_token;
        static void Main(string[] args)
        {
            String client_id = null;
            String key = null;
                foreach (String a in args)
                {
                    if (a.StartsWith("-client_id="))
                        client_id = a.Split('=')[1];
                    if (a.StartsWith("-key="))
                        key = a.Split('=')[1];
                }
                
            if (args.Length <2 || client_id == null || key == null)
            {
                Console.WriteLine("specify -client_id= -key=");
                Environment.Exit(1);
            }
            
                Console.Write(client_id + " " + key);
                JWT j = new JWT(client_id, key);
         }
        public JWT(String client_id, String key)
        {
            String SCOPE = "https://www.googleapis.com/auth/shoppingapi";
            SCOPE += " " + "https://www.googleapis.com/auth/structuredcontent";
            long now = unix_timestamp();
            long exp = now + 3600;
            String jwt_header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
            String claim = "{\"iss\":\"" + client_id + "\",\"scope\":\"" +SCOPE +
                "\",\"aud\":\"https://accounts.google.com/o/oauth2/token\",\"exp\":" + 
                exp + ",\"iat\":" + now + "}";
            System.Text.ASCIIEncoding e = new System.Text.ASCIIEncoding();
            String clearjwt = Base64UrlEncode(e.GetBytes(jwt_header)) + "." + 
                Base64UrlEncode(e.GetBytes(claim));
            byte[] buffer = Encoding.Default.GetBytes(clearjwt);
            X509Certificate2 cert = new X509Certificate2(key, "notasecret");                        
            CspParameters cp = new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider",
                ((RSACryptoServiceProvider)cert.PrivateKey).CspKeyContainerInfo.KeyContainerName);
            RSACryptoServiceProvider provider = new RSACryptoServiceProvider(cp);
            byte[] signature;
            signature = provider.SignData(buffer, "SHA256");
            string assertion = clearjwt + "." + Base64UrlEncode(signature);
            WebClient client = new WebClient();
            NameValueCollection formData = new NameValueCollection();
            formData["grant_type"] = "assertion";
            formData["assertion_type"] = "http://oauth.net/grant_type/jwt/1.0/bearer";
            formData["assertion"] = assertion;
            client.Headers["Content-type"] = "application/x-www-form-urlencoded";
            try
            {
                byte[] responseBytes = client.UploadValues("https://accounts.google.com/o/oauth2/token", 
                    "POST", formData);
                string Result = Encoding.UTF8.GetString(responseBytes);
                string[] tokens = Result.Split(':');
                for (int i = 0 ; i< tokens.Length; i++)
                {
                    if (tokens[i].Contains("access_token"))
                         this.lauth_token = (tokens[i + 1].Split(',')[0].Replace("\"", ""));
                }
                Console.WriteLine(Result);
                Console.ReadLine();
            }
            catch (WebException ex)
            {
                Stream receiveStream = ex.Response.GetResponseStream();
                Encoding encode = System.Text.Encoding.GetEncoding("utf-8");
                StreamReader readStream = new StreamReader(receiveStream, encode);
                string pageContent = readStream.ReadToEnd();
                Console.WriteLine("Error: " + pageContent);
            }
        }
        private  long unix_timestamp()
        {
            TimeSpan unix_time = (System.DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0));
            return (long)unix_time.TotalSeconds;
        }
        private  string Base64UrlEncode(byte[] ix)
        {
            var ret = Convert.ToBase64String(ix);
            ret = ret.Replace("=",String.Empty); 
            ret = ret.Replace('+', '-'); 
            ret = ret.Replace('/', '_'); 
            return ret;
        }
        public String auth_token()
        {
            return this.lauth_token;
        }
    }
}
