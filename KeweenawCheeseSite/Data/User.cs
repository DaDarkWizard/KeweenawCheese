using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KeweenawCheeseSite.Data
{
    public class User : DiscordUser
    {
        public Int64 DiscordId { get; set; }

        public string DisplayName { get; set; }

        public string Discriminator { get; set; }

        public string Avatar { get; set; }
    }
}
