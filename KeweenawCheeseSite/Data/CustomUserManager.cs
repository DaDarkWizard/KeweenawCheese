using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace KeweenawCheeseSite.Data
{
    public class CustomUserManager : UserManager<DiscordUser>
    {
        public CustomUserManager(IUserStore<DiscordUser> store, IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<DiscordUser> passwordHasher, IEnumerable<IUserValidator<DiscordUser>> userValidators,
            IEnumerable<IPasswordValidator<DiscordUser>> passwordValidators, ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors, IServiceProvider services, ILogger<UserManager<DiscordUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        public override ILogger Logger { get => base.Logger; set => base.Logger = value; }

        public override bool SupportsUserAuthenticationTokens => false;

        public override bool SupportsUserAuthenticatorKey => false;

        public override bool SupportsUserTwoFactorRecoveryCodes => false;

        public override bool SupportsUserTwoFactor => false;

        public override bool SupportsUserPassword => false;

        public override bool SupportsUserSecurityStamp => false;

        public override bool SupportsUserRole => base.SupportsUserRole;

        public override bool SupportsUserLogin => base.SupportsUserLogin;

        public override bool SupportsUserEmail => false;

        public override bool SupportsUserPhoneNumber => false;

        public override bool SupportsUserClaim => base.SupportsUserClaim;

        public override bool SupportsUserLockout => false;

        public override bool SupportsQueryableUsers => base.SupportsQueryableUsers;

        public override IQueryable<DiscordUser> Users => base.Users;

        protected override CancellationToken CancellationToken => base.CancellationToken;

        public override Task<IdentityResult> AccessFailedAsync(DiscordUser user)
        {
            return base.AccessFailedAsync(user);
        }

        public override Task<IdentityResult> AddClaimAsync(DiscordUser user, Claim claim)
        {
            return base.AddClaimAsync(user, claim);
        }

        public override Task<IdentityResult> AddClaimsAsync(DiscordUser user, IEnumerable<Claim> claims)
        {
            return base.AddClaimsAsync(user, claims);
        }

        public override Task<IdentityResult> AddLoginAsync(DiscordUser user, UserLoginInfo login)
        {
            return base.AddLoginAsync(user, login);
        }

        public override Task<IdentityResult> AddPasswordAsync(DiscordUser user, string password)
        {
            return base.AddPasswordAsync(user, password);
        }

        public override Task<IdentityResult> AddToRoleAsync(DiscordUser user, string role)
        {
            return base.AddToRoleAsync(user, role);
        }

        public override Task<IdentityResult> AddToRolesAsync(DiscordUser user, IEnumerable<string> roles)
        {
            return base.AddToRolesAsync(user, roles);
        }

        public override Task<IdentityResult> ChangeEmailAsync(DiscordUser user, string newEmail, string token)
        {
            return base.ChangeEmailAsync(user, newEmail, token);
        }

        public override Task<IdentityResult> ChangePasswordAsync(DiscordUser user, string currentPassword, string newPassword)
        {
            return base.ChangePasswordAsync(user, currentPassword, newPassword);
        }

        public override Task<IdentityResult> ChangePhoneNumberAsync(DiscordUser user, string phoneNumber, string token)
        {
            return base.ChangePhoneNumberAsync(user, phoneNumber, token);
        }

        public override Task<bool> CheckPasswordAsync(DiscordUser user, string password)
        {
            return base.CheckPasswordAsync(user, password);
        }

        public override Task<IdentityResult> ConfirmEmailAsync(DiscordUser user, string token)
        {
            return base.ConfirmEmailAsync(user, token);
        }

        public override Task<int> CountRecoveryCodesAsync(DiscordUser user)
        {
            return base.CountRecoveryCodesAsync(user);
        }

        public async override Task<IdentityResult> CreateAsync(DiscordUser user)
        {
            var cancelToken = new CancellationToken();
            return await Store.CreateAsync(user, cancelToken);
        }

        public override Task<IdentityResult> CreateAsync(DiscordUser user, string password)
        {
            return base.CreateAsync(user, password);
        }

        public override Task<byte[]> CreateSecurityTokenAsync(DiscordUser user)
        {
            return base.CreateSecurityTokenAsync(user);
        }

        public override Task<IdentityResult> DeleteAsync(DiscordUser user)
        {
            return base.DeleteAsync(user);
        }

        public override bool Equals(object obj)
        {
            return base.Equals(obj);
        }

        public override Task<DiscordUser> FindByEmailAsync(string email)
        {
            return base.FindByEmailAsync(email);
        }

        public override Task<DiscordUser> FindByIdAsync(string userId)
        {
            return base.FindByIdAsync(userId);
        }

        public override Task<DiscordUser> FindByLoginAsync(string loginProvider, string providerKey)
        {
            
            return base.FindByLoginAsync(loginProvider, providerKey);
        }

        public override Task<DiscordUser> FindByNameAsync(string userName)
        {
            return base.FindByNameAsync(userName);
        }

        public override Task<string> GenerateChangeEmailTokenAsync(DiscordUser user, string newEmail)
        {
            return base.GenerateChangeEmailTokenAsync(user, newEmail);
        }

        public override Task<string> GenerateChangePhoneNumberTokenAsync(DiscordUser user, string phoneNumber)
        {
            return base.GenerateChangePhoneNumberTokenAsync(user, phoneNumber);
        }

        public override Task<string> GenerateConcurrencyStampAsync(DiscordUser user)
        {
            return base.GenerateConcurrencyStampAsync(user);
        }

        public override Task<string> GenerateEmailConfirmationTokenAsync(DiscordUser user)
        {
            return base.GenerateEmailConfirmationTokenAsync(user);
        }

        public override string GenerateNewAuthenticatorKey()
        {
            return base.GenerateNewAuthenticatorKey();
        }

        public override Task<IEnumerable<string>> GenerateNewTwoFactorRecoveryCodesAsync(DiscordUser user, int number)
        {
            return base.GenerateNewTwoFactorRecoveryCodesAsync(user, number);
        }

        public override Task<string> GeneratePasswordResetTokenAsync(DiscordUser user)
        {
            return base.GeneratePasswordResetTokenAsync(user);
        }

        public override Task<string> GenerateTwoFactorTokenAsync(DiscordUser user, string tokenProvider)
        {
            return base.GenerateTwoFactorTokenAsync(user, tokenProvider);
        }

        public override Task<string> GenerateUserTokenAsync(DiscordUser user, string tokenProvider, string purpose)
        {
            return base.GenerateUserTokenAsync(user, tokenProvider, purpose);
        }

        public override Task<int> GetAccessFailedCountAsync(DiscordUser user)
        {
            return base.GetAccessFailedCountAsync(user);
        }

        public override Task<string> GetAuthenticationTokenAsync(DiscordUser user, string loginProvider, string tokenName)
        {
            return base.GetAuthenticationTokenAsync(user, loginProvider, tokenName);
        }

        public override Task<string> GetAuthenticatorKeyAsync(DiscordUser user)
        {
            return base.GetAuthenticatorKeyAsync(user);
        }

        public async override Task<IList<Claim>> GetClaimsAsync(DiscordUser user)
        {
            //var claims = await base.GetClaimsAsync(user);
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("urn:discord:avatar:hash", user.Avatar));
            claims.Add(new Claim("urn:discord:avatar:url", $"https://cdn.discordapp.com/avatars/{user.Id}/{user.Avatar}.png"));
            return claims;
        }

        public override Task<string> GetEmailAsync(DiscordUser user)
        {
            return base.GetEmailAsync(user);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public override Task<bool> GetLockoutEnabledAsync(DiscordUser user)
        {
            return base.GetLockoutEnabledAsync(user);
        }

        public override Task<DateTimeOffset?> GetLockoutEndDateAsync(DiscordUser user)
        {
            return base.GetLockoutEndDateAsync(user);
        }

        public override Task<IList<UserLoginInfo>> GetLoginsAsync(DiscordUser user)
        {
            return base.GetLoginsAsync(user);
        }

        public override Task<string> GetPhoneNumberAsync(DiscordUser user)
        {
            return base.GetPhoneNumberAsync(user);
        }

        public override Task<IList<string>> GetRolesAsync(DiscordUser user)
        {
            return base.GetRolesAsync(user);
        }

        public override Task<string> GetSecurityStampAsync(DiscordUser user)
        {
            return base.GetSecurityStampAsync(user);
        }

        public override Task<bool> GetTwoFactorEnabledAsync(DiscordUser user)
        {
            return base.GetTwoFactorEnabledAsync(user);
        }

        public override Task<DiscordUser> GetUserAsync(ClaimsPrincipal principal)
        {
            return base.GetUserAsync(principal);
        }

        public override string GetUserId(ClaimsPrincipal principal)
        {
            return base.GetUserId(principal);
        }

        public override Task<string> GetUserIdAsync(DiscordUser user)
        {
            return base.GetUserIdAsync(user);
        }

        public override string GetUserName(ClaimsPrincipal principal)
        {
            return base.GetUserName(principal);
        }

        public override Task<string> GetUserNameAsync(DiscordUser user)
        {
            return base.GetUserNameAsync(user);
        }

        public override Task<IList<DiscordUser>> GetUsersForClaimAsync(Claim claim)
        {
            return base.GetUsersForClaimAsync(claim);
        }

        public override Task<IList<DiscordUser>> GetUsersInRoleAsync(string roleName)
        {
            return base.GetUsersInRoleAsync(roleName);
        }

        public override Task<IList<string>> GetValidTwoFactorProvidersAsync(DiscordUser user)
        {
            return base.GetValidTwoFactorProvidersAsync(user);
        }

        public override Task<bool> HasPasswordAsync(DiscordUser user)
        {
            return base.HasPasswordAsync(user);
        }

        public override Task<bool> IsEmailConfirmedAsync(DiscordUser user)
        {
            return base.IsEmailConfirmedAsync(user);
        }

        public override Task<bool> IsInRoleAsync(DiscordUser user, string role)
        {
            return base.IsInRoleAsync(user, role);
        }

        public override Task<bool> IsLockedOutAsync(DiscordUser user)
        {
            return base.IsLockedOutAsync(user);
        }

        public override Task<bool> IsPhoneNumberConfirmedAsync(DiscordUser user)
        {
            return base.IsPhoneNumberConfirmedAsync(user);
        }

        public override string NormalizeEmail(string email)
        {
            return base.NormalizeEmail(email);
        }

        public override string NormalizeName(string name)
        {
            return base.NormalizeName(name);
        }

        public override Task<IdentityResult> RedeemTwoFactorRecoveryCodeAsync(DiscordUser user, string code)
        {
            return base.RedeemTwoFactorRecoveryCodeAsync(user, code);
        }

        public override void RegisterTokenProvider(string providerName, IUserTwoFactorTokenProvider<DiscordUser> provider)
        {
            base.RegisterTokenProvider(providerName, provider);
        }

        public override Task<IdentityResult> RemoveAuthenticationTokenAsync(DiscordUser user, string loginProvider, string tokenName)
        {
            return base.RemoveAuthenticationTokenAsync(user, loginProvider, tokenName);
        }

        public override Task<IdentityResult> RemoveClaimAsync(DiscordUser user, Claim claim)
        {
            return base.RemoveClaimAsync(user, claim);
        }

        public override Task<IdentityResult> RemoveClaimsAsync(DiscordUser user, IEnumerable<Claim> claims)
        {
            return base.RemoveClaimsAsync(user, claims);
        }

        public override Task<IdentityResult> RemoveFromRoleAsync(DiscordUser user, string role)
        {
            return base.RemoveFromRoleAsync(user, role);
        }

        public override Task<IdentityResult> RemoveFromRolesAsync(DiscordUser user, IEnumerable<string> roles)
        {
            return base.RemoveFromRolesAsync(user, roles);
        }

        public override Task<IdentityResult> RemoveLoginAsync(DiscordUser user, string loginProvider, string providerKey)
        {
            return base.RemoveLoginAsync(user, loginProvider, providerKey);
        }

        public override Task<IdentityResult> RemovePasswordAsync(DiscordUser user)
        {
            return base.RemovePasswordAsync(user);
        }

        public override Task<IdentityResult> ReplaceClaimAsync(DiscordUser user, Claim claim, Claim newClaim)
        {
            return base.ReplaceClaimAsync(user, claim, newClaim);
        }

        public override Task<IdentityResult> ResetAccessFailedCountAsync(DiscordUser user)
        {
            return base.ResetAccessFailedCountAsync(user);
        }

        public override Task<IdentityResult> ResetAuthenticatorKeyAsync(DiscordUser user)
        {
            return base.ResetAuthenticatorKeyAsync(user);
        }

        public override Task<IdentityResult> ResetPasswordAsync(DiscordUser user, string token, string newPassword)
        {
            return base.ResetPasswordAsync(user, token, newPassword);
        }

        public override Task<IdentityResult> SetAuthenticationTokenAsync(DiscordUser user, string loginProvider, string tokenName, string tokenValue)
        {
            return base.SetAuthenticationTokenAsync(user, loginProvider, tokenName, tokenValue);
        }

        public override Task<IdentityResult> SetEmailAsync(DiscordUser user, string email)
        {
            return base.SetEmailAsync(user, email);
        }

        public override Task<IdentityResult> SetLockoutEnabledAsync(DiscordUser user, bool enabled)
        {
            return base.SetLockoutEnabledAsync(user, enabled);
        }

        public override Task<IdentityResult> SetLockoutEndDateAsync(DiscordUser user, DateTimeOffset? lockoutEnd)
        {
            return base.SetLockoutEndDateAsync(user, lockoutEnd);
        }

        public override Task<IdentityResult> SetPhoneNumberAsync(DiscordUser user, string phoneNumber)
        {
            return base.SetPhoneNumberAsync(user, phoneNumber);
        }

        public override Task<IdentityResult> SetTwoFactorEnabledAsync(DiscordUser user, bool enabled)
        {
            return base.SetTwoFactorEnabledAsync(user, enabled);
        }

        public override Task<IdentityResult> SetUserNameAsync(DiscordUser user, string userName)
        {
            return base.SetUserNameAsync(user, userName);
        }

        public override string ToString()
        {
            return base.ToString();
        }

        public override Task<IdentityResult> UpdateAsync(DiscordUser user)
        {
            return base.UpdateAsync(user);
        }

        public override Task UpdateNormalizedEmailAsync(DiscordUser user)
        {
            return base.UpdateNormalizedEmailAsync(user);
        }

        public override Task UpdateNormalizedUserNameAsync(DiscordUser user)
        {
            return base.UpdateNormalizedUserNameAsync(user);
        }

        public override Task<IdentityResult> UpdateSecurityStampAsync(DiscordUser user)
        {
            return base.UpdateSecurityStampAsync(user);
        }

        public override Task<bool> VerifyChangePhoneNumberTokenAsync(DiscordUser user, string token, string phoneNumber)
        {
            return base.VerifyChangePhoneNumberTokenAsync(user, token, phoneNumber);
        }

        public override Task<bool> VerifyTwoFactorTokenAsync(DiscordUser user, string tokenProvider, string token)
        {
            return base.VerifyTwoFactorTokenAsync(user, tokenProvider, token);
        }

        public override Task<bool> VerifyUserTokenAsync(DiscordUser user, string tokenProvider, string purpose, string token)
        {
            return base.VerifyUserTokenAsync(user, tokenProvider, purpose, token);
        }

        protected override string CreateTwoFactorRecoveryCode()
        {
            return base.CreateTwoFactorRecoveryCode();
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        protected override Task<IdentityResult> UpdatePasswordHash(DiscordUser user, string newPassword, bool validatePassword)
        {
            return base.UpdatePasswordHash(user, newPassword, validatePassword);
        }

        protected override Task<IdentityResult> UpdateUserAsync(DiscordUser user)
        {
            return base.UpdateUserAsync(user);
        }

        protected override Task<PasswordVerificationResult> VerifyPasswordAsync(IUserPasswordStore<DiscordUser> store, DiscordUser user, string password)
        {
            return base.VerifyPasswordAsync(store, user, password);
        }
    }
}
