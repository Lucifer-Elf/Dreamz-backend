using Makaan.Domain.Model;
using Makaan.DTO;
using AutoMapper;
using Core.Library;
using Core.Library.Configurations;
using Core.Library.HttpContextData;
using Core.Library.Logging;
using Core.Library.OtpClient;
using Core.Library.Sms;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static Core.Library.CoreEnums;
using Makaan.Domain;
using Makaan.Domain.Utilities;

namespace AuthenticationServize.Domain.Repository
{
    public class AccountRepository
    {
        private const string _id = @"id";
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly TokenValidationParameters _tokenValidationParameter;
        private readonly OtpGenerator _otpGenerator;
        private readonly IMapper _mapper;

        public AccountRepository(UserManager<User> userManager,
                                 RoleManager<IdentityRole> roleManager,
                                 SignInManager<User> signInManager,
                                 ApplicationDbContext context,
                                 TokenValidationParameters tokenValidationParameter,
                                 OtpGenerator otpGenerator, IMapper mapper)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _context = context;
            _tokenValidationParameter = tokenValidationParameter;
            _otpGenerator = otpGenerator;
            _mapper = mapper;
        }
        public async Task<Response<AuthSuccessResponse>> AddUserToIdentityWithSpecificRoles(RegistrationInputRequest model)
        {
            try
            {
                var userExist = _context.Users.Where(i => i.Email == model.Email || i.PhoneNumber == model.PhoneNumber).FirstOrDefault();
                if (userExist != null)
                {
                    return new Response<AuthSuccessResponse>("User with this Email AlreadyExist", StatusCodes.Status409Conflict);
                }
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    return new Response<AuthSuccessResponse>("User with this Email AlreadyExist", StatusCodes.Status409Conflict);
                }

                User user = new()
                {
                    UserName = model.PhoneNumber,
                    Email = model.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    PhoneNumber = model.PhoneNumber,
                    EmailConfirmed = true,
                    PhoneNumberConfirmed = true,                 
                    
                };
                Response<AuthSuccessResponse> response = await CreateNewUserBasedOnRole(user, model);
                if (response.IsSuccessStatusCode())
                {
                    await _context.SaveChangesAsync();
                    return new Response<AuthSuccessResponse>(response.Resource, response.StatusCode);
                }
                if (user != null)
                    await _userManager.DeleteAsync(user);
                return new Response<AuthSuccessResponse>(response.Message, response.StatusCode);
            }
            catch (Exception ex)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                    await _userManager.DeleteAsync(user);
                Logger.LogError(ex);
                return new Response<AuthSuccessResponse>("Error while creating User", StatusCodes.Status500InternalServerError);
            }
        }

        private async Task<Response<AuthSuccessResponse>> CreateNewUserBasedOnRole(User user, RegistrationInputRequest model)
        {
            try
            {
                Logger.LogInformation(0, "create User");
                var createUser = await _userManager.CreateAsync(user, model.Password);

                if (createUser == null)
                    return new Response<AuthSuccessResponse>("Unable to create User", StatusCodes.Status500InternalServerError);

                if (!createUser.Succeeded)
                    return new Response<AuthSuccessResponse>(message: createUser.Errors.Select(x => x.Code).FirstOrDefault()?.ToString(), StatusCodes.Status400BadRequest);

                Logger.LogInformation(0, "create Role");
                await CreateRoleInDatabase();
                if (await _roleManager.RoleExistsAsync(Makaan.Domain.Utilities.Utility.GetRoleForstring(model.Role)))
                {
                    var result = await _userManager.AddToRoleAsync(user, Makaan.Domain.Utilities.Utility.GetRoleForstring(model.Role));
                    if (!result.Succeeded)
                        return new Response<AuthSuccessResponse>("error while creating Roles for User", StatusCodes.Status500InternalServerError);
                }

                Logger.LogInformation(0, "Generate User Token");
                var response = await GenerateAuthenticationTokenForUser(user);
                if (response.IsSuccessStatusCode())
                    return new Response<AuthSuccessResponse>(response.Resource, response.StatusCode);
                return new Response<AuthSuccessResponse>(response.Message, response.StatusCode);
            }
            catch (Exception e)
            {
                if (user != null)
                    await _userManager.DeleteAsync(user);
                Logger.LogError(e);
                return new Response<AuthSuccessResponse>("error while creating new User", StatusCodes.Status500InternalServerError);
            }
        }

       /* public async Task<Response<AuthSuccessResponse>> HandleFacebookLogin(ExternalFacebookLoginRequest externalInputModel)
        {
            try
            {
                var user = await _userManager.FindByLoginAsync(externalInputModel.Provider, externalInputModel.Email);

                if (user != null)
                    return new Response<AuthSuccessResponse>("user already exist", StatusCodes.Status409Conflict);

                user = await _userManager.FindByEmailAsync(externalInputModel.Email);
                if (user == null)
                {
                    RegistrationInputRequest register = new()
                    {
                        Email = externalInputModel.Email,
                        FirstName = externalInputModel.Name,
                        LastName = externalInputModel.LastName,
                        Role = externalInputModel.Role
                    };
                    await AddUserToIdentityWithSpecificRoles(register);

                }
                var info = new UserLoginInfo(externalInputModel.Provider, externalInputModel.Email, externalInputModel.Provider.ToUpperInvariant());
                var result = await _userManager.AddLoginAsync(user, info);
                if (!result.Succeeded)
                    return new Response<AuthSuccessResponse>(result.Errors.ToString(), statusCode: StatusCodes.Status500InternalServerError);
                var userRoles = await _userManager.GetRolesAsync(user);
                Response<AuthSuccessResponse> response = await GenerateAuthenticationTokenForUser(user);
                if (response.IsSuccessStatusCode())
                {
                    await _context.SaveChangesAsync();
                    return new Response<AuthSuccessResponse>(response.Resource, response.StatusCode);
                }
                return new Response<AuthSuccessResponse>(response.Message, response.StatusCode);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return new Response<AuthSuccessResponse>("Error while Google Login", StatusCodes.Status500InternalServerError);
            }
            finally
            {
                Logger.LogInformation(0, "Google login service finished");
            }
        }*/

        public async Task<Response<bool>> DisableUserAccountAsync(ClaimsPrincipal user)
        {
            try
            {
                string userId = AuthenticationPrincipals.GetLoginUserId(user);
                if (string.IsNullOrEmpty(userId))
                    return new Response<bool>($"UnAuthorized User", StatusCodes.Status401Unauthorized);

                var existinguser = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);
                if (existinguser == null)
                    return new Response<bool>($"User id doesnt exist", StatusCodes.Status404NotFound);
                existinguser.IsDisabled = true;
                _context.Update(existinguser);
                await _context.SaveChangesAsync();
                return new Response<bool>(true, StatusCodes.Status200OK);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return new Response<bool>("Error Disabling Users", StatusCodes.Status500InternalServerError);
            }

        }

        public async Task<Response<AuthSuccessResponse>> VerifyOtp(string code, RegistrationInputRequest request)
        {
            try
            {
                string secret = request.PhoneNumber;
                if (_otpGenerator.VerifyOtp(code, secret))
                {
                    Response<AuthSuccessResponse> response = await AddUserToIdentityWithSpecificRoles(request);
                    if (response.IsSuccessStatusCode())
                    {
                        return response;
                    }
                    else
                        return new Response<AuthSuccessResponse>(response.Message, response.StatusCode);

                }
                else
                    return new Response<AuthSuccessResponse>(@"TryAgain", StatusCodes.Status401Unauthorized);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return new Response<AuthSuccessResponse>(@"error While Otp", StatusCodes.Status500InternalServerError); ;
            }
        }

        public async Task<Response<string>> SendOtpAsync(string phoneNumber)
        {
            try
            {
                if (string.IsNullOrEmpty(phoneNumber) || !phoneNumber.Contains("+"))
                    return new Response<string>(@"Phone number error", StatusCodes.Status400BadRequest);

                var code = _otpGenerator.GetOtpValue(phoneNumber);
                var value = await SMSAuthService.SendOtpSMSAsync(phoneNumber, code);
                if (!value)
                    return new Response<string>($"error on SMS service ", StatusCodes.Status500InternalServerError);

                return new Response<string>(code, StatusCodes.Status200OK);
            }
            catch
            {
                return new Response<string>(@"ServerError", StatusCodes.Status500InternalServerError);
            }
        }

        public async Task<Response<UserDTO>> UpdateUserDetailsAsync(ClaimsPrincipal user, UserDTO userDTO)
        {
            try
            {
                if (userDTO == null)
                    return new Response<UserDTO>("Request Not Parsable", StatusCodes.Status400BadRequest);

                string userId = AuthenticationPrincipals.GetLoginUserId(user);
                if (string.IsNullOrEmpty(userId))
                    return new Response<UserDTO>($"UnAuthorized User", StatusCodes.Status401Unauthorized);
                var existinguser = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);
                if (existinguser == null)
                    return new Response<UserDTO>($"User id doesnt exist", StatusCodes.Status404NotFound);

               /* existinguser.FirstName = userDTO.FirstName;
                existinguser.LastName = userDTO.LastName;
                existinguser.CompanyName = userDTO.CompanyName;
                existinguser.CompanyRegistrationNumber = userDTO.CompanyRegistrationNumber;
                existinguser.OfficeNumber = userDTO.OfficeNumber;
                existinguser.EmiratesId = userDTO.EmiratesId;
                existinguser.Avatar = userDTO.Avatar;
                existinguser.Disable = userDTO.Disable;*/
                await _userManager.UpdateAsync(existinguser);
                await _context.SaveChangesAsync();
                return new Response<UserDTO>(userDTO, StatusCodes.Status200OK);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return new Response<UserDTO>("Error While Getting Data", StatusCodes.Status500InternalServerError);
            }
        }

        public async Task<Response<UserDTO>> GetUserDetailsAsync(ClaimsPrincipal user)
        {
            try
            {
                string userId = AuthenticationPrincipals.GetLoginUserId(user);
                if (string.IsNullOrEmpty(userId))
                    return new Response<UserDTO>($"UnAuthorized User", StatusCodes.Status401Unauthorized);
                var existinguser = await _userManager.FindByIdAsync(userId).ConfigureAwait(false);
                if (existinguser == null)
                    return new Response<UserDTO>($"User id doesnt exist", StatusCodes.Status404NotFound);

                var userDto = _mapper.Map<UserDTO>(existinguser);
                return new Response<UserDTO>(userDto, StatusCodes.Status200OK);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return new Response<UserDTO>("Error While Getting Data", StatusCodes.Status500InternalServerError);
            }
        }

        public async Task<Response<IList<UserDTO>>> GetAllUserDetailsAsync(ClaimsPrincipal user, string role)
        {
            try
            {
                string userId = AuthenticationPrincipals.GetLoginUserId(user);
                if (string.IsNullOrEmpty(userId))
                    return new Response<IList<UserDTO>>($"UnAuthorized User", StatusCodes.Status401Unauthorized);

                List<User> users;

                if (string.IsNullOrEmpty(role))
                {
                    users = await _userManager.Users.ToListAsync();
                }
                else
                {
                    var usersWithRole = await _userManager.GetUsersInRoleAsync(role);
                    users = usersWithRole.ToList();
                }
                
                if (users.Count <= 0)
                    return new Response<IList<UserDTO>>($"Users Not exist", StatusCodes.Status204NoContent);

                var userDto = _mapper.Map<IList<UserDTO>>(users);
                return new Response<IList<UserDTO>>(userDto, StatusCodes.Status200OK);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return new Response<IList<UserDTO>>("Error While Getting Data", StatusCodes.Status500InternalServerError);
            }
        }

        /*public async Task<Response<AuthSuccessResponse>> HandleGoogleLogin(ExternalLoginRequest externalInputModel)
        {
            Logger.LogInformation(0, "Google login service started");
            try
            {
                var payload = GoogleJsonWebSignature.ValidateAsync(externalInputModel.TokenId, new GoogleJsonWebSignature.ValidationSettings()).Result;

                var user = await _userManager.FindByLoginAsync(externalInputModel.Provider, payload.Subject);

                if (user != null)
                    return new Response<AuthSuccessResponse>("user already exist", StatusCodes.Status409Conflict);

                user = await _userManager.FindByEmailAsync(payload.Email);
                if (user == null)
                {
                    RegistrationInputRequest register = new()
                    {
                        Email = payload.Email,
                        FirstName = payload.GivenName,
                        LastName = payload.FamilyName,
                        Role = externalInputModel.Role
                    };
                    await AddUserToIdentityWithSpecificRoles(register);

                }
                var info = new UserLoginInfo(externalInputModel.Provider, payload.Subject, externalInputModel.Provider.ToUpperInvariant());
                var result = await _userManager.AddLoginAsync(user, info);
                if (!result.Succeeded)
                    return new Response<AuthSuccessResponse>(result.Errors.ToString(), statusCode: StatusCodes.Status500InternalServerError);


                var userRoles = await _userManager.GetRolesAsync(user);
                Response<AuthSuccessResponse> response = await GenerateAuthenticationTokenForUser(user);
                if (response.IsSuccessStatusCode())
                {
                    await _context.SaveChangesAsync();
                    return new Response<AuthSuccessResponse>(response.Resource, response.StatusCode);
                }

                return new Response<AuthSuccessResponse>(response.Message, response.StatusCode);

            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return new Response<AuthSuccessResponse>("Error while Google Login", StatusCodes.Status500InternalServerError);
            }
            finally
            {
                Logger.LogInformation(0, "Google login service finished");
            }
        }*/

        // All Private function listed down
        private async Task CreateRoleInDatabase()
        {
            // creating Roles In Database.
            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.Customer))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Customer));
        
        }

        private async Task<Response<AuthSuccessResponse>> GenerateAuthenticationTokenForUser(User user)
        {
            try
            {
                var userRoles = await _userManager.GetRolesAsync(user);
                if (userRoles.Count <= 0)
                {
                    return new Response<AuthSuccessResponse>("Error while Finding Roles for User", StatusCodes.Status500InternalServerError);
                }
                var authSignInKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration.GetValue<string>("app_auth_secret")));
                var tokendescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                      new Claim(JwtRegisteredClaimNames.Sub,user.Email),
                      new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                      new Claim(JwtRegisteredClaimNames.Email,user.Email),
                      new Claim(ClaimTypes.Role,userRoles.First()),
                      new Claim(_id,user.Id)
                }),

                    Expires = DateTime.Now.AddMinutes(15),
                    SigningCredentials = new SigningCredentials(authSignInKey, SecurityAlgorithms.HmacSha256)
                };

                foreach (var userRole in userRoles)
                {
                    tokendescriptor.Subject.AddClaim(new Claim(ClaimTypes.Role, userRole));
                }

                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokendescriptor);

                var refreshToken = new RefreshToken
                {
                    JwtId = token.Id,
                    IsUsed = false,
                    IsRevorked = false,
                    UserId = user.Id,
                    CreationDate = DateTime.Now,
                    ExpiryDate = DateTime.Now.AddMinutes(15),
                    Token = RandomString(45) + Guid.NewGuid()
                };
                await _context.RefreshToken.AddAsync(refreshToken);
               // var userDto = _mapper.Map<UserMetaData>(user);
                var succesResponse = new AuthSuccessResponse
                {
                    Token = tokenHandler.WriteToken(token),
                    RefreshToken = refreshToken.Token,
                   // MetaData = userDto
                };
                Logger.LogInformation(0, "Generated jwt Token successfully");
                return new Response<AuthSuccessResponse>(succesResponse, StatusCodes.Status201Created);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return new Response<AuthSuccessResponse>("Error while generating Token", StatusCodes.Status500InternalServerError);
            }
        }
        private string RandomString(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@!|$/*-";
            return new string(Enumerable.Repeat(chars, length).Select(x => x[random.Next(x.Length)]).ToArray());
        }
        public async Task<Response<AuthSuccessResponse>> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                // validate existence of token
                var storedRefreshToken = await _context.RefreshToken.FirstOrDefaultAsync(x => x.Token == refreshToken);
                if (storedRefreshToken == null)
                    return new Response<AuthSuccessResponse>("Token doesnt Exist", StatusCodes.Status500InternalServerError);
                // validate id used
                if (storedRefreshToken.IsUsed)
                    return new Response<AuthSuccessResponse>("Token has been used", StatusCodes.Status500InternalServerError);
                //validate if revorked
                if (storedRefreshToken.IsRevorked)
                    return new Response<AuthSuccessResponse>("Token has been revorked", StatusCodes.Status500InternalServerError);
                storedRefreshToken.IsRevorked = true;
                storedRefreshToken.IsUsed = true;
                _context.RefreshToken.Update(storedRefreshToken);
                var user = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
                Response<AuthSuccessResponse> response = await GenerateAuthenticationTokenForUser(user);
                if (response.IsSuccessStatusCode())
                {
                    await _context.SaveChangesAsync();
                    return new Response<AuthSuccessResponse>(response.Resource, response.StatusCode);
                }
                return new Response<AuthSuccessResponse>(response.Message, response.StatusCode);
            }
            catch (Exception e)
            {
                Logger.LogError(e);
                return new Response<AuthSuccessResponse>("Error while token verification", StatusCodes.Status500InternalServerError);
            }
        }
        private ClaimsPrincipal? GetClaimAndVerifyToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var principal = tokenHandler.ValidateToken(token, _tokenValidationParameter, out var validatedToken);
                if (!IsJwtWithValidSecurityAlogorithm(validatedToken))
                {
                    return null;
                }
                return principal;
            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return null;
            }
        }
        private bool IsJwtWithValidSecurityAlogorithm(SecurityToken validateToken)
        {
            return validateToken is JwtSecurityToken jwtSecurityToken &&
                jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
        }
        public async Task<Response<AuthSuccessResponse>> UserVerification(string phoneNumber)
        {
            User existedUser = await _userManager.FindByNameAsync(phoneNumber);
            if (existedUser == null)
            {
                return new Response<AuthSuccessResponse>("user Doesnt Exist", StatusCodes.Status404NotFound);
            }
            var code = await _userManager.GenerateUserTokenAsync(existedUser, "Phone", "login-validation");
            var value = await SMSAuthService.SendOtpSMSAsync(phoneNumber, code);
            if (!value)
                return new Response<AuthSuccessResponse>($"error on SMS service ", StatusCodes.Status500InternalServerError);
            return new Response<AuthSuccessResponse>($"SmsSendSucessFully {code}", StatusCodes.Status200OK);
        }

        public async Task<Response<AuthSuccessResponse>> Login(string code, string phoneNumber)
        {
            User existedUser = await _userManager.FindByNameAsync(phoneNumber);
            if (existedUser == null)
            {
                return new Response<AuthSuccessResponse>("user Doesnt Exist", StatusCodes.Status404NotFound);
            }
            var isValid = await _userManager.VerifyUserTokenAsync(existedUser, "Phone", "login-validation", code);
            if (isValid)
            {
                Response<AuthSuccessResponse> response = await GenerateAuthenticationTokenForUser(existedUser);
                if (response.IsSuccessStatusCode())
                {
                    await _context.SaveChangesAsync();
                    return new Response<AuthSuccessResponse>(response.Resource, StatusCodes.Status200OK);
                }
                return new Response<AuthSuccessResponse>("error while Login", StatusCodes.Status500InternalServerError);
            }
            return new Response<AuthSuccessResponse>("error while Login", StatusCodes.Status500InternalServerError);
        }


        public async Task<Response<AuthSuccessResponse>> HandleLoginRequest(InputLoginModel model)
        {
            SignInResult result;
            User existedUser;
            if (!string.IsNullOrEmpty(model.Email))
            {
                existedUser = await _userManager.FindByEmailAsync(model.Email);
                if (existedUser == null)
                {
                    return new Response<AuthSuccessResponse>("user Doesnt Exist", StatusCodes.Status404NotFound);
                }
                result = await _signInManager.PasswordSignInAsync(existedUser, model.Password, model.RememberMe, false);
            }
            else
            {
                existedUser = await _userManager.FindByNameAsync(model.PhoneNumber);
                if (existedUser == null)
                {
                    return new Response<AuthSuccessResponse>("user Doesnt Exist", StatusCodes.Status404NotFound);
                }
                result = await _signInManager.PasswordSignInAsync(model.PhoneNumber, model.Password, model.RememberMe, false);
            }
            bool isRoleExist = false;
            List<string> role = (List<string>)await _userManager.GetRolesAsync(existedUser);
            if (role.Contains(model.Role.ToLower()))
                isRoleExist = true;
            if (isRoleExist && result.Succeeded)
            {
                Response<AuthSuccessResponse> response = await GenerateAuthenticationTokenForUser(existedUser);
                if (response.IsSuccessStatusCode())
                {
                    await _context.SaveChangesAsync();
                    return new Response<AuthSuccessResponse>(response.Resource, StatusCodes.Status200OK);
                }
                return new Response<AuthSuccessResponse>("error while Login", StatusCodes.Status500InternalServerError);
            }
            return new Response<AuthSuccessResponse>("error while Login", StatusCodes.Status500InternalServerError);
        }
        public async Task<Response<InputLoginModel>> HandleChangedPassword(ChangePasswordRequest changepassword)
        {
            try
            {
                var userExist = await _userManager.FindByIdAsync(changepassword.UserId);
                if (userExist == null)
                    return new Response<InputLoginModel>("No able to find User of specific Id", StatusCodes.Status404NotFound);
                var passWordMatch = await _userManager.CheckPasswordAsync(userExist, changepassword.OldPasword);
                if (!passWordMatch)
                    return new Response<InputLoginModel>("Old Password is not correct", StatusCodes.Status406NotAcceptable);
                var isNewPassWord = await _userManager.ChangePasswordAsync(userExist, changepassword.OldPasword, changepassword.NewPassword);
                if (isNewPassWord.Succeeded)
                    return new Response<InputLoginModel>("Password Changed Successfully", StatusCodes.Status200OK);
                return new Response<InputLoginModel>(isNewPassWord.Errors.ToString(), StatusCodes.Status406NotAcceptable);
            }
            catch
            {
                return new Response<InputLoginModel>("Error while Changing Password", StatusCodes.Status500InternalServerError);
            }
        }
        public async Task<Response> RevokeTokens(string refreshToken)
        {
            try
            {
                // validate existence of token
                var storedRefreshToken = await _context.RefreshToken.FirstOrDefaultAsync(x => x.Token == refreshToken);
                if (storedRefreshToken != null)
                {
                    storedRefreshToken.IsRevorked = true;
                    storedRefreshToken.IsUsed = true;
                    _context.RefreshToken.Update(storedRefreshToken);
                    await _context.SaveChangesAsync();
                    return new Response("Revoked", statusCode: StatusCodes.Status200OK);
                }
                return new Response("Bad Request", statusCode: StatusCodes.Status400BadRequest);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex);
                return new Response("Error in logout service", statusCode: StatusCodes.Status400BadRequest);
            }
        }               
    }
}
