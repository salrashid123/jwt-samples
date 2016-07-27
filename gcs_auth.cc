#include <stdio.h>
#include <iostream>
#include <string.h>
#include <ctime>
#include <math.h>
#include <algorithm>

#include <sstream>
#include <stdexcept>
#include <iomanip>

#include <curl/curl.h>

#include <openssl/sha.h>  
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h> 
#include <openssl/bio.h>

using namespace std;

/*

apt-get install libcurl4-openssl-dev libssl-dev
g++  -std=c++11 -o gcs_auth gcs_auth.cc -lcurl -lcrypto 
./gcs_auth
{
  "access_token" : "ya29.3QDSgqs9QupWd2eqLdxrhu-vAVSdI35Ol2In61TymxxxxmC17pmf-G2y9KTqSTQPPFHGcOTsXEA",
  "token_type" : "Bearer",
  "expires_in" : 3600
}

This script acquires an oauth2 bearer access_token use with authenticated GCS 
ShoppingAPI and ContentAPI requests.  GCS customers should use one of the 
libraries shown below to get the token in a production setting.  This script 
is provided to  demonstrate the encryption and structure of getting an oauth2 
bearer tokens. Ensure the computer this script is run on is synced with a 
NTP server.

>> this code hans't been duration-tested in prod; may have a memory leak or two. <<

references/citations:

http://www.programmershare.com/1248592/
https://github.com/peervpn/peervpn/blob/master/libp2psec/rsa.c
http://sehermitage.web.fc2.com/program/src/rsacrypt.c
http://www.cplusplus.com/forum/unices/45878/
http://stackoverflow.com/questions/5288076/doing-base64-encoding-and-decoding-in-openssl-c
and others i thoughtlessly omitted

openssl pkcs12 -in xxxxyyyy.p12 -nocerts -out privateKey.pem
echo -n plainText | openssl dgst -sha256
(stdin)= 3ec8d98e737b84ff4fa0a9f0943d32bca35fcc73

*/

string data;

size_t writeCallback(char* buf, size_t size, size_t nmemb, void* up)
{ 
    for (int c = 0; c<size*nmemb; c++)
    {
        data.push_back(buf[c]);
    }
    return size*nmemb;
}

char *base64(const void *input, int length)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);
  char *buff = (char *)malloc(bptr->length);
  memcpy(buff, bptr->data, bptr->length-1);

  buff[bptr->length-1] = 0;
  BIO_free_all(b64);
  return buff;
}

char * doSign(char*certFile,const char* pwd, string plainText)
{

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char sign[256];
    unsigned int signLen;

    FILE* fp;
    if (!(fp = fopen(certFile, "rb"))) 
    { 
        fprintf(stderr, "Error opening file %s\n", certFile);        
        return NULL;     
    }    
    PKCS12 *p12= d2i_PKCS12_fp(fp, NULL);  
    fclose (fp);    
    if (!p12) {      
        fprintf(stderr, "Error reading PKCS#12 file\n");   
        ERR_print_errors_fp(stderr);  
        return NULL;   
    } 
     
    EVP_PKEY *pkey=NULL;     
    X509 *x509=NULL;
    STACK_OF(X509) *ca = NULL;
    if (!PKCS12_parse(p12, pwd, &pkey, &x509, &ca)) {         
        fprintf(stderr, "Error parsing PKCS#12 file\n");       
        ERR_print_errors_fp(stderr);
        return NULL;
    } 
    PKCS12_free(p12);

    int sigLen=EVP_PKEY_size(pkey);
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    EVP_MD_CTX_init(ctx);

    RSA *prikey = EVP_PKEY_get1_RSA(pkey); 

   SHA256_CTX sha256;
   SHA256_Init(&sha256);
   const char * c = plainText.c_str();
   SHA256_Update(&sha256, c, strlen(c));
   SHA256_Final(hash, &sha256);

    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    //cout << "Text to sign ----->  " << plainText << "\n";
    //cout << "==================\n";    
    //cout << "SHA256:  " << ss.str() << "\n";
    //cout << "==================\n";

    int ret = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,  &signLen, prikey);

    EVP_MD_CTX_destroy(ctx);
    RSA_free(prikey);
    EVP_PKEY_free(pkey);  
    X509_free(x509);

    return base64(sign,signLen);
}

int main(int argc, char* argv[]) {
    
    std::string SCOPE = "https://www.googleapis.com/auth/devstorage.read_write";
    char* certFile = (char*)"aaabbbbb.p12";
    std::string iss = "xxxxyyyyy@developer.gserviceaccount.com";

    std:string jwt_header = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    long now = std::time(0);
    std::string expire_on = std::to_string(now + 3600);
    string claim ="{\"iss\":\"" + iss + "\",\"scope\":\"" + SCOPE + "\",\"aud\":\"https://accounts.google.com/o/oauth2/token\",\"exp\":" + expire_on + ",\"iat\":" + std::to_string(now) + "}";
    //cout << "Clear text to sign ---> " << jwt_header << "." << claim << "\n";
    //cout << "==================\n";
    char* b64jwt = base64(jwt_header.c_str(), jwt_header.size());
    char* b64claim = base64(claim.c_str(), claim.size());    
    std::string jwt = std::string(b64jwt) + "." + std::string(b64claim);

    CRYPTO_malloc_init();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms(); 
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();

    const char* passwd = "notasecret";
    char * e = doSign(certFile,passwd,jwt);  

    EVP_cleanup();
    //cout << "Signature: " << e << "\n";
    //cout << "jwt: =======\n" << jwt << "\n";
    std::string assertion = jwt + "." + e;
    //cout << "jwt + assertion ============\n" << assertion << "\n"; 

    replace(assertion.begin(),  assertion.end(),'+','-');
    replace(assertion.begin(),  assertion.end(),'/','_');
    //replace(assertion.begin(),  assertion.end(),'=','*');

    CURL* curl;

    curl_global_init(CURL_GLOBAL_ALL);
    curl=curl_easy_init();

    curl_easy_setopt(curl, CURLOPT_URL, "https://accounts.google.com/o/oauth2/token");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &writeCallback);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L); 

    curl_easy_setopt(curl, CURLOPT_POST, 1);
    std::string  postfields =  std::string("grant_type=assertion&assertion_type=http%3A%2F%2Foauth.net%2Fgrant_type%2Fjwt%2F1.0%2Fbearer&assertion=") + assertion.c_str() ; 

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields.c_str());    
    curl_easy_perform(curl);
    cout << endl << data << endl;
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}
