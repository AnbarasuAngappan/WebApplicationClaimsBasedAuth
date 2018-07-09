using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace WebApplicationClaimsBasedAuth.Data
{
    public class ClaimData
    {
        public static List<string> UserClaims { get; set; } = new List<string> { "canCreate", "canEdit", "canDelete" };
    }
}