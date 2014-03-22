using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using AspNetMvcGetTwitterData.Common;
using AspNetMvcGetTwitterData.Enums;
using AspNetMvcGetTwitterData.ViewModels;

namespace AspNetMvcGetTwitterData.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {

            return View();
        }

        [HttpPost]
        public ActionResult Index(Twitter twitter)
        {
            var oAuth = TwitterManager.SetTwitterKey();
            return Redirect(oAuth.AuthorizationLinkGet());
        }

        public ActionResult Auth()
        {
            if (!string.IsNullOrEmpty(Request["OAuth_token"]) && !string.IsNullOrEmpty(Request["oauth_verifier"]))
            {
                var oAuth = TwitterManager.SetTwitterKey();
                var twitterManager = new TwitterManager();
                oAuth.AccessTokenGet(Request["OAuth_token"], Request["oauth_verifier"]);
                if (oAuth.TokenSecret.Length > 0)
                {
                    const string url = "https://api.twitter.com/1.1/account/verify_credentials.json";
                    var requestResult = oAuth.oAuthWebRequest(OAuthMethodOption.GET, url, String.Empty);
                    var twitter = new Twitter();
                    twitter = twitterManager.SetTwitterStats(requestResult, twitter);

                    const int mentionCount = 0;    
                    twitter.MentionCount = mentionCount;
                    twitter.SessionToken = oAuth.Token + "||" + oAuth.TokenSecret;

                }
            }
            return RedirectToAction("Index", "Home");
        }
    }
}
