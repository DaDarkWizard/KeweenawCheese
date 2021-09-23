using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace KeweenawCheeseSite.Data
{
    public class CustomUserStore : IUserStore<DiscordUser>, IUserLoginStore<DiscordUser>
    {
        public Task AddLoginAsync(DiscordUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public async Task<IdentityResult> CreateAsync(DiscordUser user, CancellationToken cancellationToken)
        {
            var context = CustomDbContext.CreateContext();
            var discordUser = await context.DiscordUsers.FirstOrDefaultAsync(x => x.Id == user.Id);
            if(discordUser != null)
            {
                return IdentityResult.Failed(null);
            }

            discordUser = new DiscordUser()
            { 
                Id = user.Id,
                Discriminator = user.Discriminator,
                Avatar = user.Avatar,
                DisplayName = user.DisplayName
            };

            context.Add(discordUser);
            await context.SaveChangesAsync();
            await context.DisposeAsync();
            return IdentityResult.Success;
            
        }

        public Task<IdentityResult> DeleteAsync(DiscordUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            //throw new NotImplementedException();
        }

        public async Task<DiscordUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var context = CustomDbContext.CreateContext();
            Int64 intId;
            var parsed = Int64.TryParse(userId, out intId);
            if (parsed)
            {
                var user = await context.DiscordUsers.FirstOrDefaultAsync(x => x.Id == intId);
                return user;
            }
            else
            {
                return null;
            }
        }

        public async Task<DiscordUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            if(loginProvider == "Discord")
            {
                return await FindByIdAsync(providerKey, cancellationToken);
            }
            else
            {
                return null;
            }
        }

        public Task<DiscordUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            return null;
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(DiscordUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public async Task<string> GetNormalizedUserNameAsync(DiscordUser user, CancellationToken cancellationToken)
        {
            return user.DisplayName;
        }

        public Task<string> GetUserIdAsync(DiscordUser user, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                return user.Id.ToString();
            });
        }

        public async Task<string> GetUserNameAsync(DiscordUser user, CancellationToken cancellationToken)
        {
            return user.DisplayName + "#" + user.Discriminator;
        }

        public Task RemoveLoginAsync(DiscordUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetNormalizedUserNameAsync(DiscordUser user, string normalizedName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetUserNameAsync(DiscordUser user, string userName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> UpdateAsync(DiscordUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
    }
}
