using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AspNetMvcGetTwitterData.ViewModels
{
    public class Twitter  
    {
        public string TwitterId { get; set; }
        public string SessionToken { get; set; }
        public string Name { get; set; }
        public string ScreenName { get; set; }
        public string WebSite { get; set; }
        public string PictureUrl { get; set; }
        public string Description { get; set; }
        public string Location { get; set; }
        public int? FollowerCount { get; set; }
        public int? TweetCount { get; set; }
        public int? MentionCount { get; set; }
        public int? FriendCount { get; set; }
        public DateTime? AccountCreateDate { get; set; }
        public bool? IsApiKeyNew { get; set; }
        public DateTime? CreateDate { get; set; }
        public DateTime? EditDate { get; set; }   
    }
}