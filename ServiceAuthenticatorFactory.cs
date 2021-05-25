using HawkNet;
using HawkNet.WCF;
using Microsoft.ServiceModel.Web;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Activation;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;

namespace JMFamily.WCF.ServiceAuthenticator
{
    public class ServiceAuthenticatorFactory : ServiceHostFactory
    {
        public ServiceHost CreateHost(Type serviceType, Uri[] baseAddresses)
        {
            return this.CreateServiceHost(serviceType, baseAddresses);
        }

        protected override ServiceHost CreateServiceHost(Type serviceType, Uri[] baseAddresses)
        {
            int timeskew;

            if (ConfigurationManager.AppSettings["HawkTimeSkewSeconds"] == null ||
                !int.TryParse(ConfigurationManager.AppSettings["HawkTimeSkewSeconds"], out timeskew))
            {
                timeskew = 300;
            }

            Func<string, HawkCredential> credentials = id =>
            {
                string key = ConfigurationManager.AppSettings["HawkKey"];
                if (key != null)
                {
                    return new HawkCredential
                    {
                        Id = id,
                        Key = key,
                        Algorithm = "sha256",
                        User = id
                    };
                }

                return null;
            };

            var result = new WebServiceHost2(serviceType, true, baseAddresses);

            var hawkInterceptor = new HawkRequestInterceptor(
                credentials,
                true,
                null,
                timeskew);

            var jwtInterceptor = new JwtInterceptor(ConfigurationManager.AppSettings["TenantId"],
                ConfigurationManager.AppSettings["Audience"].Split(';'));

            var allInterceptors = new Dictionary<string, RequestInterceptor>();
            allInterceptors.Add("Hawk", hawkInterceptor);
            allInterceptors.Add("Bearer", jwtInterceptor);

            var authenticator = new ServiceAuthenticationInterceptor(allInterceptors, GetEndpointFilter);

            result.Interceptors.Add(authenticator);

            return result;

        }

        private static bool GetEndpointFilter(Message request)
        {
            if (request.Properties.Via.AbsoluteUri.ToLower().EndsWith("$metadata"))
                return false;

            if (ConfigurationManager.AppSettings["AllowedIPAddresses"] == null)
                return true;

            var allowedIPs = ConfigurationManager.AppSettings["AllowedIPAddresses"].Split(';');

            string clientIp = GetIpAddress(request);

            return !allowedIPs.Any(ip => ip == clientIp);
        }

        private static string GetIpAddress(Message request)
        {
            if (request.Properties.ContainsKey(RemoteEndpointMessageProperty.Name))
            {
                RemoteEndpointMessageProperty prop;
                prop = (RemoteEndpointMessageProperty)request.Properties[RemoteEndpointMessageProperty.Name];
                return prop.Address;
            }
            else
            {
                return null;
            }
        }
    }
}
