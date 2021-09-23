using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace KeweenawCheeseSite.Data
{
    public class CustomClaimsPrincipalFactory : IUserClaimsPrincipalFactory<DiscordUser>
    {
        public Task<ClaimsPrincipal> CreateAsync(DiscordUser user)
        {
            throw new NotImplementedException();
        }
    }
}
