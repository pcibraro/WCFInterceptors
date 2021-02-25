using Microsoft.ServiceModel.Web;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.ServiceModel.Channels;
using System.Text;

namespace JMFamily.WCF.ServiceAuthenticator
{
    public class ServiceAuthenticationInterceptor : RequestInterceptor
    {
        static TraceSource TraceSource = new TraceSource("JMFamily.WCF.ServiceAuthentication");

        IDictionary<string, RequestInterceptor> innerInterceptors;

        public ServiceAuthenticationInterceptor(IDictionary<string, RequestInterceptor> innerInterceptors) : base(false)
        {
            this.innerInterceptors = innerInterceptors;
        }

        public override void ProcessRequest(ref System.ServiceModel.Channels.RequestContext requestContext)
        {
            var requestMessage = requestContext.RequestMessage;

            var request = (HttpRequestMessageProperty)requestMessage.Properties[HttpRequestMessageProperty.Name];

            var authHeader = request.Headers["Authorization"];

            var interceptorFound = false;

            if (authHeader != null)
            {
                foreach (var innerInterceptor in this.innerInterceptors)
                {
                    if(authHeader.StartsWith(innerInterceptor.Key, StringComparison.InvariantCultureIgnoreCase))
                    {
                        interceptorFound = true;

                        innerInterceptor.Value.ProcessRequest(ref requestContext);

                        break;
                    }
                }
            }

            if(!interceptorFound) 
            {
                var reply = Message.CreateMessage(MessageVersion.None, null);
                var responseProperty = new HttpResponseMessageProperty() { StatusCode = HttpStatusCode.Unauthorized };

                reply.Properties[HttpResponseMessageProperty.Name] = responseProperty;
                requestContext.Reply(reply);

                requestContext = null;
            }
        }
    }
}
