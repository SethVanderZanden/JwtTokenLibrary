using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWTLibrary
{
    /// <summary>
    /// Custom middleware for validating a JWT token in the middleware
    /// </summary>
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // reject any non https requests
            if (context.Request.IsHttps == false) return;

            // skip requests for logging in since they cant have a valid token yet
            if(context.Request.Path == "/api/User/Login") await _next(context);
            else if(context.Request.Path == "/api/User/Register") await _next(context);
            else
            {
                // enable buffering so the request doesnt get emptied. 
                context.Request.EnableBuffering();
                string token = context.Request.Headers["Authorization"];

                if (token != null)
                {
                    if (JwtSettings.VerifyToken(token)) await _next(context);

                    else
                    {
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync("Invalid Access");
                        return;
                    }
                }
                else
                {
                    context.Response.StatusCode = 401;
                    await context.Response.WriteAsync("Invalid Access");
                    return;
                }
            }
        }
    }

    public static class JwtMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtMiddleware(
            this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<JwtMiddleware>();
        }
    }
}
