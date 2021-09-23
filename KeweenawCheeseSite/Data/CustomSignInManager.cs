using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace KeweenawCheeseSite.Data
{
    public class CustomSignInManager : SignInManager<DiscordUser>
    {
        public CustomSignInManager(UserManager<DiscordUser> userManager, IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<DiscordUser> claimsFactory, IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<DiscordUser>> logger, IAuthenticationSchemeProvider schemes,
            IUserConfirmation<DiscordUser> confirmation)
            : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
        {
        }

        public override ILogger Logger { get => base.Logger; set => base.Logger = value; }

        public override Task<bool> CanSignInAsync(DiscordUser user)
        {
            return base.CanSignInAsync(user);
        }

        public override Task<SignInResult> CheckPasswordSignInAsync(DiscordUser user, string password, bool lockoutOnFailure)
        {
            return base.CheckPasswordSignInAsync(user, password, lockoutOnFailure);
        }

        public override AuthenticationProperties ConfigureExternalAuthenticationProperties(string provider, string redirectUrl, string userId = null)
        {
            return base.ConfigureExternalAuthenticationProperties(provider, redirectUrl, userId);
        }

        public async override Task<ClaimsPrincipal> CreateUserPrincipalAsync(DiscordUser user)
        {
            var principal = await base.CreateUserPrincipalAsync(user);
            foreach(var claim in await UserManager.GetClaimsAsync(user))
            {
                principal.Claims.Append(claim);
            }
            return principal;
        }

        public override bool Equals(object obj)
        {
            return base.Equals(obj);
        }

        public async override Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent)
        {
            return SignInResult.Success;
            //return base.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent);
        }

        public async override Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey, bool isPersistent, bool bypassTwoFactor)
        {
            var user = await UserManager.FindByLoginAsync(loginProvider, providerKey);
            await SignInWithClaimsAsync(user, isPersistent, new List<Claim>()
            {
                new Claim("urn:discord:avatar:url", $"https://cdn.discordapp.com/avatars/{user.Id}/{user.Avatar}.png"),
                new Claim("urn:discord:avatar:hash", user.Avatar)
            });
            return SignInResult.Success;
           //return await base.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent, bypassTwoFactor);
        }

        public override Task ForgetTwoFactorClientAsync()
        {
            return base.ForgetTwoFactorClientAsync();
        }

        public override Task<IEnumerable<AuthenticationScheme>> GetExternalAuthenticationSchemesAsync()
        {
            return base.GetExternalAuthenticationSchemesAsync();
        }

        public override Task<ExternalLoginInfo> GetExternalLoginInfoAsync(string expectedXsrf = null)
        {
            
            return base.GetExternalLoginInfoAsync(expectedXsrf);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public override Task<DiscordUser> GetTwoFactorAuthenticationUserAsync()
        {
            return base.GetTwoFactorAuthenticationUserAsync();
        }

        public override bool IsSignedIn(ClaimsPrincipal principal)
        {
            return base.IsSignedIn(principal);
        }

        public override Task<bool> IsTwoFactorClientRememberedAsync(DiscordUser user)
        {
            return base.IsTwoFactorClientRememberedAsync(user);
        }

        public override Task<SignInResult> PasswordSignInAsync(DiscordUser user, string password, bool isPersistent, bool lockoutOnFailure)
        {
            return base.PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
        }

        public override Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {
            return base.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure);
        }

        public override Task RefreshSignInAsync(DiscordUser user)
        {
            return base.RefreshSignInAsync(user);
        }

        public override Task RememberTwoFactorClientAsync(DiscordUser user)
        {
            return base.RememberTwoFactorClientAsync(user);
        }

        public async override Task SignInAsync(DiscordUser user, bool isPersistent, string authenticationMethod = null)
        {
            await base.SignInAsync(user, isPersistent, authenticationMethod);
        }

        public override Task SignInAsync(DiscordUser user, AuthenticationProperties authenticationProperties, string authenticationMethod = null)
        {
            return base.SignInAsync(user, authenticationProperties, authenticationMethod);
        }

        public override Task SignInWithClaimsAsync(DiscordUser user, bool isPersistent, IEnumerable<Claim> additionalClaims)
        {
            return base.SignInWithClaimsAsync(user, isPersistent, additionalClaims);
        }

        public override Task SignInWithClaimsAsync(DiscordUser user, AuthenticationProperties authenticationProperties, IEnumerable<Claim> additionalClaims)
        {
            return base.SignInWithClaimsAsync(user, authenticationProperties, additionalClaims);
        }

        public override Task SignOutAsync()
        {
            return base.SignOutAsync();
        }

        public override string ToString()
        {
            return base.ToString();
        }

        public override Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
        {
            return base.TwoFactorAuthenticatorSignInAsync(code, isPersistent, rememberClient);
        }

        public override Task<SignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode)
        {
            return base.TwoFactorRecoveryCodeSignInAsync(recoveryCode);
        }

        public override Task<SignInResult> TwoFactorSignInAsync(string provider, string code, bool isPersistent, bool rememberClient)
        {
            return base.TwoFactorSignInAsync(provider, code, isPersistent, rememberClient);
        }

        public override Task<IdentityResult> UpdateExternalAuthenticationTokensAsync(ExternalLoginInfo externalLogin)
        {
            return base.UpdateExternalAuthenticationTokensAsync(externalLogin);
        }

        public override Task<DiscordUser> ValidateSecurityStampAsync(ClaimsPrincipal principal)
        {
            return base.ValidateSecurityStampAsync(principal);
        }

        public override Task<bool> ValidateSecurityStampAsync(DiscordUser user, string securityStamp)
        {
            return base.ValidateSecurityStampAsync(user, securityStamp);
        }

        public override Task<DiscordUser> ValidateTwoFactorSecurityStampAsync(ClaimsPrincipal principal)
        {
            return base.ValidateTwoFactorSecurityStampAsync(principal);
        }

        protected override Task<bool> IsLockedOut(DiscordUser user)
        {
            return base.IsLockedOut(user);
        }

        protected override Task<SignInResult> LockedOut(DiscordUser user)
        {
            return base.LockedOut(user);
        }

        protected override Task<SignInResult> PreSignInCheck(DiscordUser user)
        {
            return base.PreSignInCheck(user);
        }

        protected override Task ResetLockout(DiscordUser user)
        {
            return base.ResetLockout(user);
        }

        protected override Task<SignInResult> SignInOrTwoFactorAsync(DiscordUser user, bool isPersistent, string loginProvider = null, bool bypassTwoFactor = false)
        {
            return base.SignInOrTwoFactorAsync(user, isPersistent, loginProvider, bypassTwoFactor);
        }
    }
}
