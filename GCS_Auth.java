/* Copyright (c) 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

import org.apache.commons.codec.binary.Base64;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.io.*;
import java.net.*;

/**
This script acquires an oauth2 bearer access_token use with authenticated GCS 
ShoppingAPI and ContentAPI requests.  GCS customers should use one of the 
libraries shown below to get the token in a production setting.  This script 
is provided to  demonstrate the encryption and structure of getting an oauth2 
bearer tokens. Ensure the computer this script is run on is synced with a 
NTP server.

REFERENCE :
https://developers.google.com/commerce-search/docs/shopping_auth
https://developers.google.com/accounts/docs/OAuth2ServiceAccount
http://code.google.com/p/google-api-java-client/wiki/OAuth2
   
   javac -cp .:commons-codec-1.6.jar GCS_Auth.java
   
   java -cp .:commons-codec-1.6.jar GCS_Auth --client_id= --key= 
   
     client_id=<clientID Service account  'email'>    
     key = <private key for the service account>
     
  This code is not supported by Google
*/

public class GCS_Auth {

	private String access_token = null;
	public static void main(String[] args) {
		String client_id = null;
		String key = null;
		
		for (String a :args)
		{
			if (a.startsWith("--key="))
				key = a.split("=")[1];
			if (a.startsWith("--client_id="))
				client_id = a.split("=")[1];				
		}
		
		if ((args.length < 2) || client_id == null || key == null)
		{
			System.out.println("specify --key= --client_id=");
			System.exit(-1);
		}   

		GCS_Auth j = new GCS_Auth(client_id, key);
	}

	public GCS_Auth(String client_id, String key)
	{
		String SCOPE = "https://www.googleapis.com/auth/shoppingapi";
		SCOPE =  SCOPE + " " + "https://www.googleapis.com/auth/structuredcontent";
		try{
			String jwt_header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

			long now = System.currentTimeMillis() / 1000L;
			long exp = now + 3600;
			String iss = client_id;
		    String claim ="{\"iss\":\"" + iss + "\",\"scope\":\"" + SCOPE + "\",\"aud\":\"https://accounts.google.com/o/oauth2/token\",\"exp\":" + exp + ",\"iat\":" + now + "}"; 

		    String jwt = Base64.encodeBase64URLSafeString(jwt_header.getBytes()) + "." + Base64.encodeBase64URLSafeString(claim.getBytes("UTF-8"));
		    
			byte[] jwt_data = jwt.getBytes("UTF8");

	    	Signature sig = Signature.getInstance("SHA256WithRSA");
	    	
	    	KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
	    	ks.load(new FileInputStream(key),"notasecret".toCharArray());
	    	
	         sig.initSign((PrivateKey)ks.getKey("privatekey", "notasecret".toCharArray()));
	    	 sig.update(jwt_data);
	    	 byte[] signatureBytes = sig.sign();
	    	 String b64sig = Base64.encodeBase64URLSafeString(signatureBytes);
	    	 
	    	 String assertion = jwt + "." + b64sig;
	    	 
	    	 //System.out.println("Assertion: " + assertion);
	    	 
	    	 String data = "grant_type=assertion";
	    	 data += "&" + "assertion_type"+ "=" + URLEncoder.encode("http://oauth.net/grant_type/jwt/1.0/bearer", "UTF-8");
	    	 data += "&" + "assertion=" + URLEncoder.encode(assertion, "UTF-8");

	    	 URLConnection conn = null;
	    	 try{
	    	    URL url = new URL("https://accounts.google.com/o/oauth2/token");
	    	    conn = url.openConnection();
	    	    conn.setDoOutput(true);
	    	    OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
	    	    wr.write(data);
	    	    wr.flush();

	    	    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
	    	    String line;
	    	    while ((line = rd.readLine()) != null) {
    	    		if (line.split(":").length > 0)
    	    			if (line.split(":")[0].trim().equals("\"access_token\""))
    	    			  access_token = line.split(":")[1].trim().replace("\"","").replace(",", "");
	    	    	System.out.println(line);
	    	    }
	    	    wr.close();
	    	    rd.close();	
	    	 }
	    	 catch (Exception ex)
	    	 {
	    	  	InputStream error = ((HttpURLConnection) conn).getErrorStream();
	    	   	BufferedReader br
	    	       	= new BufferedReader(new InputStreamReader(error));    	 
	    	    	StringBuilder sb = new StringBuilder();	    	 
	    	    	String line;
	    	    	while ((line = br.readLine()) != null) {
	    	    		sb.append(line);
	    	    	} 
	    	    	System.out.println ("Error: " + ex +"\n " + sb.toString());
	    	    }
	    	 //System.out.println(access_token);
		}
		catch (Exception ex)
		{
			System.out.println("Error: " + ex);
		}
	}
	private String access_token() {
		return access_token;
	}
}
