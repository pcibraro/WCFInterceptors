using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.ServiceModel.Web;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;

namespace JMFamily.WCF.ServiceAuthenticator
{
    public class JwtInterceptor : RequestInterceptor
    {
        const string Scheme = "Bearer";

        static TraceSource TraceSource = new TraceSource("JMFamily.WCF.ServiceAuthentication.JWT");

        Predicate<System.ServiceModel.Channels.Message> endpointFilter;
        string tenantId;
        string audience;

        public JwtInterceptor(string tenantId, string audience, Predicate<Message> endpointFilter = null)
            : base(false)
        {
            this.endpointFilter = endpointFilter;
            this.tenantId = tenantId;
            this.audience = audience;
        }

        public override void ProcessRequest(ref RequestContext requestContext)
        {
            if (Trace.CorrelationManager.ActivityId == Guid.Empty)
                Trace.CorrelationManager.ActivityId = Guid.NewGuid();

            var request = requestContext.RequestMessage;

            if (endpointFilter == null || endpointFilter(request))
            {
                try
                {
                    IPrincipal principal = ExtractCredentials(request);
                    if (principal != null)
                    {
                        InitializeSecurityContext(request, principal);
                    }
                    else
                    {
                        var reply = Message.CreateMessage(MessageVersion.None, null);
                        
                        var responseProperty = new HttpResponseMessageProperty() { StatusCode = HttpStatusCode.Unauthorized };

                        reply.Properties[HttpResponseMessageProperty.Name] = responseProperty;
                        requestContext.Reply(reply);

                        requestContext = null;
                    }
                }
                catch (Exception ex)
                {
                    TraceSource.TraceData(TraceEventType.Error, 0,
                        string.Format("{0} - Security Exception {1}",
                            Trace.CorrelationManager.ActivityId, ex.ToString()));

                    var reply = Message.CreateMessage(MessageVersion.None, null, (object)ex.Message);
                    var responseProperty = new HttpResponseMessageProperty() { StatusCode = HttpStatusCode.Unauthorized };

                    reply.Properties[HttpResponseMessageProperty.Name] = responseProperty;
                    requestContext.Reply(reply);

                    requestContext = null;
                }
            }
        }

        private IPrincipal ExtractCredentials(Message requestMessage)
        {
            var request = (HttpRequestMessageProperty)requestMessage.Properties[HttpRequestMessageProperty.Name];

            var authHeader = request.Headers["Authorization"];

            if (authHeader != null && authHeader.StartsWith(Scheme, StringComparison.InvariantCultureIgnoreCase))
            {
                var bearer = authHeader.Substring(Scheme.Length).Trim();

                TraceSource.TraceInformation(string.Format("{0} - Received Auth header: {1}",
                    Trace.CorrelationManager.ActivityId, bearer));

                Microsoft.IdentityModel.Tokens.SecurityToken token;

                var stsDiscoveryEndpoint = "https://login.microsoftonline.com/" + this.tenantId + "/v2.0/.well-known/openid-configuration";

                TraceSource.TraceInformation(string.Format("{0} - Retrieving keys from: {1}",
                    Trace.CorrelationManager.ActivityId, stsDiscoveryEndpoint));

                var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever());

                var config = configManager.GetConfigurationAsync().Result;

                TraceSource.TraceInformation(string.Format("{0} - Keys successfully retrieved from: {1}",
                    Trace.CorrelationManager.ActivityId, stsDiscoveryEndpoint));

                var validationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    IssuerSigningKeys = config.SigningKeys,
                    ValidateLifetime = true,
                    ValidIssuer = config.Issuer,
                    ValidAudience = this.audience
                };

                var tokendHandler = new JwtSecurityTokenHandler();

                var principal = tokendHandler.ValidateToken(bearer, validationParameters, out token);

                return principal;

            }

            return null;
        }

        private void InitializeSecurityContext(Message request, IPrincipal principal)
        {
            var policies = new List<IAuthorizationPolicy>();
            policies.Add(new PrincipalAuthorizationPolicy(principal));

            var securityContext = new ServiceSecurityContext(policies.AsReadOnly());

            if (request.Properties.Security != null)
            {
                request.Properties.Security.ServiceSecurityContext = securityContext;
            }
            else
            {
                request.Properties.Security = new SecurityMessageProperty() { ServiceSecurityContext = securityContext };
            }
        }

        class PrincipalAuthorizationPolicy : IAuthorizationPolicy
        {
            string id = Guid.NewGuid().ToString();
            IPrincipal user;

            public PrincipalAuthorizationPolicy(IPrincipal user)
            {
                this.user = user;
            }

            public ClaimSet Issuer
            {
                get { return ClaimSet.System; }
            }

            public string Id
            {
                get { return this.id; }
            }

            public bool Evaluate(EvaluationContext evaluationContext, ref object state)
            {
                evaluationContext.AddClaimSet(this, new DefaultClaimSet(Claim.CreateNameClaim(user.Identity.Name)));
                evaluationContext.Properties["Identities"] = new List<IIdentity>(new IIdentity[] { user.Identity });
                evaluationContext.Properties["Principal"] = user;
                return true;
            }
        }

    }

    
}
