using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AspNetMvcGetTwitterData.Enums   
{
    [Serializable]
    public enum TwitterSignatureTypeOption
    {
        HMACSHA1,
        PLAINTEXT,
        RSASHA1
    }
}