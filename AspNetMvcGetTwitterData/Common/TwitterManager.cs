using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using AspNetMvcGetTwitterData.Enums;
using AspNetMvcGetTwitterData.ViewModels;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AspNetMvcGetTwitterData.Common
{
    public class TwitterManager
    {
        protected class QueryParameter
        {
            private readonly string _name;
            private readonly string _value;

            public QueryParameter(string name, string value)
            {
                this._name = name;
                this._value = value;
            }

            public string Name
            {
                get { return _name; }
            }

            public string Value
            {
                get { return _value; }
            }
        }

        protected class QueryParameterComparer : IComparer<QueryParameter>
        {
            #region IComparer<QueryParameter> Members

            public int Compare(QueryParameter x, QueryParameter y)
            {
                return x.Name == y.Name ? String.CompareOrdinal(x.Value, y.Value) : String.CompareOrdinal(x.Name, y.Name);
            }

            #endregion
        }

        protected const string OAuthVersion = "1.0";
        protected const string OAuthParameterPrefix = "oauth_";

        //
        // List of know and used oauth parameters' names
        //        
        protected const string OAuthConsumerKeyKey = "oauth_consumer_key";
        protected const string OAuthCallbackKey = "oauth_callback";
        protected const string OAuthVersionKey = "oauth_version";
        protected const string OAuthSignatureMethodKey = "oauth_signature_method";
        protected const string OAuthSignatureKey = "oauth_signature";
        protected const string OAuthTimestampKey = "oauth_timestamp";
        protected const string OAuthNonceKey = "oauth_nonce";
        protected const string OAuthTokenKey = "oauth_token";
        protected const string OAuthVerifier = "oauth_verifier";
        protected const string OAuthTokenSecretKey = "oauth_token_secret";

        protected const string Hmacsha1SignatureType = "HMAC-SHA1";
        protected const string PlainTextSignatureType = "PLAINTEXT";
        protected const string Rsasha1SignatureType = "RSA-SHA1";
        public string TokenVerifier { get; set; }


        protected Random Random = new Random();

        protected string UnreservedChars = "abcçdefgğhıijklmnoöpqrsştuüvwxyzABCÇDEFGĞHIİJKLMNOÖPQRSŞTUÜVWXYZ0123456789-_.~";



        /// <summary>
        /// Helper function to compute a hash value
        /// </summary>
        /// <param name="hashAlgorithm">The hashing algoirhtm used. If that algorithm needs some initialization, like HMAC and its derivatives, they should be initialized prior to passing it to this function</param>
        /// <param name="data">The data to hash</param>
        /// <returns>a Base64 string of the hash value</returns>
        private static string ComputeHash(HashAlgorithm hashAlgorithm, string data)
        {
            if (hashAlgorithm == null)
            {
                throw new ArgumentNullException("hashAlgorithm");
            }

            if (string.IsNullOrEmpty(data))
            {
                throw new ArgumentNullException("data");
            }

            byte[] dataBuffer = Encoding.ASCII.GetBytes(data);
            byte[] hashBytes = hashAlgorithm.ComputeHash(dataBuffer);

            return Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// Internal function to cut out all non oauth query string parameters (all parameters not begining with "oauth_")
        /// </summary>
        /// <param name="parameters">The query string part of the Url</param>
        /// <returns>A list of QueryParameter each containing the parameter name and value</returns>
        private static List<QueryParameter> GetQueryParameters(string parameters)
        {
            if (parameters.StartsWith("?"))
            {
                parameters = parameters.Remove(0, 1);
            }

            var result = new List<QueryParameter>();

            if (!string.IsNullOrEmpty(parameters))
            {
                string[] p = parameters.Split('&');
                foreach (string s in p)
                {
                    if (!string.IsNullOrEmpty(s) && !s.StartsWith(OAuthParameterPrefix))
                    {
                        if (s.IndexOf('=') > -1)
                        {
                            string[] temp = s.Split('=');
                            result.Add(new QueryParameter(temp[0], temp[1]));
                        }
                        else
                        {
                            result.Add(new QueryParameter(s, string.Empty));
                        }
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// This is a different Url Encode implementation since the default .NET one outputs the percent encoding in lower case.
        /// While this is not a problem with the percent encoding spec, it is used in upper case throughout OAuth
        /// </summary>
        /// <param name="value">The value to Url encode</param>
        /// <returns>Returns a Url encoded string</returns>
        public string UrlEncode(string value)
        {
            var result = new StringBuilder();

            foreach (char symbol in value)
            {
                if (UnreservedChars.IndexOf(symbol) != -1)
                {
                    result.Append(symbol);
                }
                else
                {
                    result.Append('%' + String.Format("{0:X2}", (int)symbol));
                }
            }

            return result.ToString();
        }

        /// <summary>
        /// Normalizes the request parameters according to the spec
        /// </summary>
        /// <param name="parameters">The list of parameters already sorted</param>
        /// <returns>a string representing the normalized parameters</returns>
        protected string NormalizeRequestParameters(IList<QueryParameter> parameters)
        {
            var sb = new StringBuilder();
            QueryParameter p;
            for (int i = 0; i < parameters.Count; i++)
            {
                p = parameters[i];
                sb.AppendFormat("{0}={1}", p.Name, p.Value);

                if (i < parameters.Count - 1)
                {
                    sb.Append("&");
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// Generate the signature base that is used to produce the signature
        /// </summary>
        /// <param name="url">The full url that needs to be signed including its non OAuth url parameters</param>
        /// <param name="consumerKey">The consumer key</param>        
        /// <param name="token">The token, if available. If not available pass null or an empty string</param>
        /// <param name="tokenSecret">The token secret, if available. If not available pass null or an empty string</param>
        /// <param name="httpMethod">The http method used. Must be a valid HTTP method verb (POST,GET,PUT, etc)</param>
        /// <param name="nonce"></param>
        /// <param name="signatureType">The signature type. To use the default values use <see cref="OAuthBase.SignatureTypes">OAuthBase.SignatureTypes</see>.</param>
        /// <param name="timeStamp"></param>
        /// <param name="normalizedUrl"></param>
        /// <param name="normalizedRequestParameters"></param>
        /// <returns>The signature base</returns>
        public string GenerateSignatureBase(Uri url, string oauth_callback, string consumerKey, string token, string tokenSecret, string httpMethod, string timeStamp, string nonce, string signatureType, out string normalizedUrl, out string normalizedRequestParameters)
        {
            if (token == null)
            {
                token = string.Empty;
            }

            if (tokenSecret == null)
            {
                //tokenSecret = string.Empty;
            }

            if (string.IsNullOrEmpty(consumerKey))
            {
                throw new ArgumentNullException("consumerKey");
            }

            if (string.IsNullOrEmpty(httpMethod))
            {
                throw new ArgumentNullException("httpMethod");
            }

            if (string.IsNullOrEmpty(signatureType))
            {
                throw new ArgumentNullException("signatureType");
            }

            //normalizedUrl = null;
            //normalizedRequestParameters = null;

            List<QueryParameter> parameters = GetQueryParameters(url.Query);
            parameters.Add(new QueryParameter(OAuthVersionKey, OAuthVersion));
            parameters.Add(new QueryParameter(OAuthNonceKey, nonce));
            parameters.Add(new QueryParameter(OAuthTimestampKey, timeStamp));
            parameters.Add(new QueryParameter(OAuthSignatureMethodKey, signatureType));
            parameters.Add(new QueryParameter(OAuthConsumerKeyKey, consumerKey));
            parameters.Add(new QueryParameter(OAuthCallbackKey, oauth_callback));
            if (!string.IsNullOrEmpty(token))
            {
                parameters.Add(new QueryParameter(OAuthTokenKey, token));
            }

            if (!string.IsNullOrEmpty(TokenVerifier))
            {
                parameters.Add(new QueryParameter(OAuthVerifier, TokenVerifier));
            }

            parameters.Sort(new QueryParameterComparer());

            normalizedUrl = string.Format("{0}://{1}", url.Scheme, url.Host);
            if (!((url.Scheme == "http" && url.Port == 80) || (url.Scheme == "https" && url.Port == 443)))
            {
                normalizedUrl += ":" + url.Port;
            }
            normalizedUrl += url.AbsolutePath;
            normalizedRequestParameters = NormalizeRequestParameters(parameters);

            var signatureBase = new StringBuilder();
            signatureBase.AppendFormat("{0}&", httpMethod.ToUpper());
            signatureBase.AppendFormat("{0}&", UrlEncode(normalizedUrl));
            signatureBase.AppendFormat("{0}", UrlEncode(normalizedRequestParameters));

            return signatureBase.ToString();
        }

        /// <summary>
        /// Generate the signature value based on the given signature base and hash algorithm
        /// </summary>
        /// <param name="signatureBase">The signature based as produced by the GenerateSignatureBase method or by any other means</param>
        /// <param name="hash">The hash algorithm used to perform the hashing. If the hashing algorithm requires initialization or a key it should be set prior to calling this method</param>
        /// <returns>A base64 string of the hash value</returns>
        public string GenerateSignatureUsingHash(string signatureBase, HashAlgorithm hash)
        {
            return ComputeHash(hash, signatureBase);
        }

        /// <summary>
        /// Generates a signature using the HMAC-SHA1 algorithm
        /// </summary>		
        /// <param name="url">The full url that needs to be signed including its non OAuth url parameters</param>
        /// <param name="consumerKey">The consumer key</param>
        /// <param name="consumerSecret">The consumer seceret</param>
        /// <param name="token">The token, if available. If not available pass null or an empty string</param>
        /// <param name="tokenSecret">The token secret, if available. If not available pass null or an empty string</param>
        /// <param name="httpMethod">The http method used. Must be a valid HTTP method verb (POST,GET,PUT, etc)</param>
        /// <param name="timeStamp"></param>
        /// <param name="nonce"></param>
        /// <param name="normalizedUrl"></param>
        /// <param name="normalizedRequestParameters"></param>
        /// <returns>A base64 string of the hash value</returns>
        public string GenerateSignature(Uri url, string oauth_callback, string consumerKey, string consumerSecret, string token, string tokenSecret, string httpMethod, string timeStamp, string nonce, out string normalizedUrl, out string normalizedRequestParameters)
        {
            return GenerateSignature(url, oauth_callback, consumerKey, consumerSecret, token, tokenSecret, httpMethod, timeStamp, nonce, TwitterSignatureTypeOption.HMACSHA1, out normalizedUrl, out normalizedRequestParameters);
        }

        /// <summary>
        /// Generates a signature using the specified signatureType 
        /// </summary>		
        /// <param name="url">The full url that needs to be signed including its non OAuth url parameters</param>
        /// <param name="consumerKey">The consumer key</param>
        /// <param name="consumerSecret">The consumer seceret</param>
        /// <param name="token">The token, if available. If not available pass null or an empty string</param>
        /// <param name="tokenSecret">The token secret, if available. If not available pass null or an empty string</param>
        /// <param name="httpMethod">The http method used. Must be a valid HTTP method verb (POST,GET,PUT, etc)</param>
        /// <param name="nonce"></param>
        /// <param name="signatureType">The type of signature to use</param>
        /// <param name="timeStamp"></param>
        /// <param name="normalizedUrl"></param>
        /// <param name="normalizedRequestParameters"></param>
        /// <exception cref="NotImplementedException"></exception>
        /// <returns>A base64 string of the hash value</returns>
        public string GenerateSignature(Uri url, string oauth_callback, string consumerKey, string consumerSecret, string token, string tokenSecret, string httpMethod, string timeStamp, string nonce, TwitterSignatureTypeOption signatureType, out string normalizedUrl, out string normalizedRequestParameters)
        {
            normalizedUrl = null;
            normalizedRequestParameters = null;

            switch (signatureType)
            {
                case TwitterSignatureTypeOption.PLAINTEXT:
                    return HttpUtility.UrlEncode(string.Format("{0}&{1}", consumerSecret, tokenSecret));
                case TwitterSignatureTypeOption.HMACSHA1:
                    string signatureBase = GenerateSignatureBase(url, oauth_callback, consumerKey, token, tokenSecret, httpMethod, timeStamp, nonce, Hmacsha1SignatureType, out normalizedUrl, out normalizedRequestParameters);

                    var hmacsha1 = new HMACSHA1
                    {
                        Key = Encoding.ASCII.GetBytes(string.Format("{0}&{1}", UrlEncode(consumerSecret),
                                                                    string.IsNullOrEmpty(tokenSecret)
                                                                        ? ""
                                                                        : UrlEncode(tokenSecret)))
                    };

                    return GenerateSignatureUsingHash(signatureBase, hmacsha1);
                case TwitterSignatureTypeOption.RSASHA1:
                    throw new NotImplementedException();
                default:
                    throw new ArgumentException("Unknown signature type", "signatureType");
            }
        }

        /// <summary>
        /// Generate the timestamp for the signature        
        /// </summary>
        /// <returns></returns>
        public virtual string GenerateTimeStamp()
        {
            // Default implementation of UNIX time of the current UTC time
            TimeSpan ts = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0);
            return Convert.ToInt64(ts.TotalSeconds).ToString();
        }

        /// <summary>
        /// Generate a nonce
        /// </summary>
        /// <returns></returns>
        public virtual string GenerateNonce()
        {
            // Just a simple implementation of a random number between 123400 and 9999999
            //return Random.Next(123400, 9999999).ToString();
            return Convert.ToBase64String(new ASCIIEncoding().GetBytes(DateTime.Now.Ticks.ToString(CultureInfo.InvariantCulture)));
        }

        public static oAuthTwitter SetTwitterKey()
        {
            var oAuth = new oAuthTwitter
            {
                ConsumerKey = "your api key",
                ConsumerSecret = "your api secret",
                REQUEST_TOKEN = "https://api.twitter.com/oauth/request_token",
                ACCESS_TOKEN = "https://api.twitter.com/oauth/access_token",
                AUTHORIZE = "https://api.twitter.com/oauth/authorize"
            };
            return oAuth;
        }

        public Twitter SetTwitterStats(string requestResult)
        {
            var twitter = new Twitter();

            JObject jObject = JObject.Parse(requestResult);
            twitter.FollowerCount = (int)jObject["followers_count"];
            twitter.Name = (string)jObject["name"];
            twitter.TwitterId = Convert.ToString(jObject["id"]);
            twitter.AccountCreateDate = DateTime.ParseExact((string)jObject["created_at"], "ddd MMM dd HH:mm:ss zzz yyyy", CultureInfo.InvariantCulture);
            twitter.ScreenName = (string)jObject["screen_name"];
            var webSite = (jObject["entities"]["url"]);
            if (webSite != null)
                twitter.WebSite = (string)jObject["entities"]["url"]["urls"][0]["expanded_url"];
            twitter.Description = (string)jObject["description"];
            twitter.Location = (string)jObject["location"];
            twitter.FriendCount = (int)jObject["friends_count"];
            twitter.TweetCount = (int)jObject["statuses_count"];
            twitter.PictureUrl = (string)jObject["profile_image_url"];
            twitter.EditDate = DateTime.UtcNow;
            return twitter;
        }

        public Twitter SetTwitterStats(string requestResult, Twitter twitter)
        {

            JObject jObject = JObject.Parse(requestResult);
            twitter.FollowerCount = (int)jObject["followers_count"]; 
            twitter.Name = (string)jObject["name"];
            twitter.TwitterId = Convert.ToString(jObject["id"]);
            twitter.AccountCreateDate = DateTime.ParseExact((string)jObject["created_at"], "ddd MMM dd HH:mm:ss zzz yyyy", CultureInfo.InvariantCulture);
            twitter.ScreenName = (string)jObject["screen_name"];
            var webSite = (jObject["entities"]["url"]);
            if (webSite != null)
                twitter.WebSite = (string)jObject["entities"]["url"]["urls"][0]["expanded_url"];
            twitter.Description = (string)jObject["description"];
            twitter.Location = (string)jObject["location"];
            twitter.FriendCount = (int)jObject["friends_count"];
            twitter.TweetCount = (int)jObject["statuses_count"];
            twitter.PictureUrl = (string)jObject["profile_image_url"];
            twitter.EditDate = DateTime.UtcNow;
            return twitter;
        }

        public int MentionCount(string jsonMentionList)
        {
            dynamic jObj = JsonConvert.DeserializeObject(jsonMentionList);
            var numberOfMentions = 0;
            foreach (var text in jObj)
            {
                numberOfMentions++;
            }
            return numberOfMentions;
        }
    }

    public class oAuthTwitter : TwitterManager
    {

        #region Properties

        public string REQUEST_TOKEN { get; set; }
        public string AUTHORIZE { get; set; }
        public string ACCESS_TOKEN { get; set; }

        public string ConsumerKey { get; set; }
        public string ConsumerSecret { get; set; }

        public string Token { get; set; }
        public string TokenSecret { get; set; }
        public string oauth_callback { get; set; }

        #endregion

        /// <summary>
        /// Get the link to Twitter's authorization page for this application.
        /// </summary>
        /// <returns>The url with a valid request token, or a null string.</returns>
        public string AuthorizationLinkGet()
        {
            //oauth_callback = UrlEncode("http://localhost:53359/Home/Auth");
            string ret = null;
            //oauth_callback = "http://localhost:53359/Home/Auth";  
            string response = oAuthWebRequest(OAuthMethodOption.POST, REQUEST_TOKEN, String.Empty);
            if (response.Length > 0)   
            {
                //response contains token and token secret.  We only need the token.
                NameValueCollection qs = HttpUtility.ParseQueryString(response);

                if (qs["oauth_token"] != null)
                {
                    Token = qs["oauth_token"];
                    TokenSecret = qs["oauth_token_secret"];
                    ret = AUTHORIZE + "?oauth_token=" + Token + "&oauth_callback=" + oauth_callback;
                }
            }
            return ret;
        }

        /// <summary>
        /// Exchange the request token for an access token.
        /// </summary>
        /// <param name="authToken">The oauth_token is supplied by Twitter's authorization page following the callback.</param>
        /// <param name="oauthVerifier"></param>
        public void AccessTokenGet(string authToken, string oauthVerifier)
        {
            Token = authToken;
            TokenVerifier = oauthVerifier;
            string response = oAuthWebRequest(OAuthMethodOption.POST, ACCESS_TOKEN, String.Empty);
            if (response.Length > 0)
            {
                //Store the Token and Token Secret
                NameValueCollection qs = HttpUtility.ParseQueryString(response);
                if (qs["oauth_token"] != null)
                {
                    Token = qs["oauth_token"];
                }
                if (qs["oauth_token_secret"] != null)
                {
                    TokenSecret = qs["oauth_token_secret"];
                }
            }
        }

        /// <summary>
        /// Submit a web request using oAuth.
        /// </summary>
        /// <param name="method">GET or POST</param>
        /// <param name="url">The full url, including the querystring.</param>
        /// <param name="postData">Data to post (querystring format)</param>
        /// <returns>The web server response.</returns>
        public string
            oAuthWebRequest(OAuthMethodOption method, string url, string postData)
        {
            string outUrl;
            string querystring;

            //Setup postData for signing.
            //Add the postData to the querystring.
            if (method == OAuthMethodOption.POST)
            {
                if (postData.Length > 0)
                {
                    //Decode the parameters and re-encode using the oAuth UrlEncode method.
                    var qs = HttpUtility.ParseQueryString(postData);
                    postData = "";
                    foreach (var key in qs.AllKeys)
                    {
                        if (postData.Length > 0)
                        {
                            postData += "&";
                        }
                        qs[key] = HttpUtility.UrlDecode(qs[key]);
                        qs[key] = UrlEncode(qs[key]);
                        postData += key + "=" + qs[key];
                    }
                    if (url.IndexOf("?") > 0)
                    {
                        url += "&";
                    }
                    else
                    {
                        url += "?";
                    }
                    url += postData;
                }
            }

            var uri = new Uri(url);

            string nonce = GenerateNonce();
            string timeStamp = GenerateTimeStamp();

            //Generate Signature
            string sig = GenerateSignature(uri, oauth_callback,
                                           ConsumerKey,
                                           ConsumerSecret,
                                           Token,
                                           TokenSecret,
                                           method.ToString(),
                                           timeStamp,
                                           nonce,
                                           out outUrl,
                                           out querystring);

            querystring += "&oauth_signature=" + HttpUtility.UrlEncode(sig);
            //Convert the querystring to postData
            if (method == OAuthMethodOption.POST)
            {
                postData = querystring;
                querystring = "";
            }

            if (querystring.Length > 0)
            {
                outUrl += "?";
            }
            var ret = WebRequest(method, outUrl + querystring, postData);
            return ret;
        }

        /// <summary>
        /// Web Request Wrapper
        /// </summary>      
        /// <param name="method">Http Method</param>
        /// <param name="url">Full url to the web resource</param>
        /// <param name="postData">Data to post in querystring format</param>
        /// <returns>The web server response.</returns>
        public string WebRequest(OAuthMethodOption method, string url, string postData)
        {
            StreamWriter requestWriter;
            var webRequest = System.Net.WebRequest.Create(url) as HttpWebRequest;
            webRequest.Method = method.ToString();
            webRequest.ServicePoint.Expect100Continue = false;
            //webRequest.UserAgent  = "Identify your application please.";
            //webRequest.Timeout = 20000;
            string responseData = string.Empty;
            if (method == OAuthMethodOption.POST)
            {
                webRequest.ContentType = "application/x-www-form-urlencoded";

                //POST the data.
                requestWriter = new StreamWriter(webRequest.GetRequestStream());
                try
                {
                    requestWriter.Write(postData);
                }
                finally
                {
                    requestWriter.Close();
                    //requestWriter = null;
                }
            }
            try
            {
                responseData = WebResponseGet(webRequest);
            }
            catch (Exception)
            {

                throw;
            }


            //webRequest = null;

            return responseData;

        }

        /// <summary>
        /// Process the web response.
        /// </summary>
        /// <param name="webRequest">The request object.</param>
        /// <returns>The response data.</returns>
        public string WebResponseGet(HttpWebRequest webRequest)
        {
            StreamReader responseReader = null;
            string responseData;
            Boolean isSuccess = false;
            try
            {
                responseReader = new StreamReader(webRequest.GetResponse().GetResponseStream());
                responseData = responseReader.ReadToEnd();
                isSuccess = true;
            }
            catch (WebException we)
            {
                isSuccess = false;
                var responseTmp = we.Response as HttpWebResponse;
                responseData = Convert.ToString((int)responseTmp.StatusCode);
            }
            //finally
            //{
            //    webRequest.GetResponse().GetResponseStream().Close();
            //    responseReader.Close();
            //    //responseReader = null;
            //}
            if (isSuccess)
            {
                webRequest.GetResponse().GetResponseStream().Close();
                responseReader.Close();
            }
            return responseData;
        }
    }
}