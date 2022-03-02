using JWT;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Exceptions;
using JWT.Serializers;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace JWTLibrary
{
    /// <summary>
    /// Custom Class for setting up a email only JWT Token .. To edit the secret find the JwtSecret.xml where the DLL file is located
    /// </summary>
    public class JwtSettings
    {
        private string? Secret { get; set; }
        private const string path = "JwtSecret.txt";
        public int RefreshTokenTTL { get; set; } = 15;

        private IJwtAlgorithm Algorithm;
        private IJsonSerializer Serializer;
        private IBase64UrlEncoder UrlEncoder;
        private IDateTimeProvider Provider;
        private IJwtValidator Validator;

        public JwtSettings()
        {
            Algorithm = new HMACSHA256Algorithm();
            Serializer = new JsonNetSerializer();
            UrlEncoder = new JwtBase64UrlEncoder();
            Provider = new UtcDateTimeProvider();
            Validator = new JwtValidator(Serializer, Provider);

            if (!File.Exists(path))
            {
                using (StreamWriter sw = File.CreateText(path))
                {
                    // set default text
                    Console.WriteLine("Creating JwtSecret.txt, HIGHLY RECOMMEND CHANGING SECRET VALUE!");
                    sw.WriteLine("SecretShouldBeChanged");

                    Secret = File.ReadAllText(path);
                    
                }
            }

            else
            {
                // read in the secret
                Secret = File.ReadAllText(path);
            }

            if (Secret == null) throw new Exception("Secret is null please give it a value!");
        }

        /// <summary>
        /// Function to take a token, validate and then generate a new token and return the new token
        /// </summary>
        /// <param name="currentToken">current token</param>
        /// <returns> new token in string format</returns>
        public static string RefreshToken(string currentToken)
        {
            try
            {
                if (VerifyToken(currentToken))
                {
                    string email = GetEmailFromToken(currentToken);
                    return GenerateToken(email);
                }
                else throw new Exception();
            }
            catch
            {
                return "ERROR";
            }
        }


        /// <summary>
        ///  Generate a JWT Token utilizing a User DTO and store the generated token in the database.
        /// </summary>
        /// <param name="userDTO">DTO object</param>
        /// <returns>The token in string format.</returns>
        public static string GenerateToken(string email)
        {
            try
            {
                string token = JwtBuilder.Create()
                      .WithAlgorithm(new HMACSHA256Algorithm()) // symmetric
                      .WithSecret(new JwtSettings().Secret)
                      // make it expire in 3 days
                      .AddClaim("exp", DateTimeOffset.UtcNow.AddDays(3).ToUnixTimeSeconds())
                      .AddClaim("email", email)
                      .Encode();


                return token;
            }
            catch
            {
                return "ERROR";
            }
        }

        /// <summary>
        /// Verifies the token and then returns the email address of the token.
        /// </summary>
        /// <param name="token">Token in String format</param>
        /// <returns>Email in string format.</returns>
        public static string GetEmailFromToken(string token)
        {
            try
            {
                if (VerifyToken(token))
                {
                    JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                    JwtSecurityToken jwtSecurityToken = jwtSecurityTokenHandler.ReadJwtToken(token);

                    return jwtSecurityToken.Claims.Where(c => c.Type == "email").First().Value;
                }
                throw new Exception();
            }
            catch
            {
                return "ERROR";
            }
        }

        /// <summary>
        /// Validates token & then returns the expiration date of the token.
        /// </summary>
        /// <param name="token">Token </param>
        /// <returns>returns expiration date of a verified token in DateTime Format</returns>
        public static DateTime GetTokenExpiration(string token)
        {
            try
            {
                // our token isnt being verified
                if (VerifyToken(token))
                {
                    JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                    JwtSecurityToken jwtSecurityToken = jwtSecurityTokenHandler.ReadJwtToken(token);

                    //return DateTime.Parse(jwtSecurityToken.Claims.Where(c => c.Type == "exp").First().Value);
                    DateTimeOffset dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(long.Parse(jwtSecurityToken.Claims.Where(c => c.Type == "exp").First().Value));
                    return dateTimeOffset.UtcDateTime;
                }
                throw new Exception();
            }
            catch
            {
                return new DateTime();
            }
        }

        /// <summary>
        /// Verify A token utilizing our JWT Security Token Handler. 
        /// </summary>
        /// <param name="token">The Token in question.</param>
        /// <returns>True if the token is verified. False if not verified.</returns>
        public static bool VerifyToken(string token)
        {
            try
            {
                JwtSettings jwtSettings = new JwtSettings();
                IJwtDecoder decoder = new JwtDecoder(jwtSettings.Serializer, jwtSettings.Validator, jwtSettings.UrlEncoder, jwtSettings.Algorithm);
                JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(new JwtSettings().Secret)),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time
                    ClockSkew = TimeSpan.Zero
                };

                // validate the token 
                jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);

                return true;
            }
            catch (TokenExpiredException)
            {
                return false;
            }
            catch (SignatureVerificationException)
            {
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
