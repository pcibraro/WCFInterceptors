using HawkNet;
using JMFamily.WCF.ServiceAuthenticator;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace ServiceAuthenticator.Sample
{
    public class MyServiceAuthenticatorFactory : ServiceAuthenticatorFactory
    {
        protected override Func<string, HawkCredential> GetCredentials()
        {
            Func<string, HawkCredential> credentials = id =>
            {
                string key = ConfigurationManager.AppSettings["HawkKey"];
                if (key != null)
                {
                    return new HawkCredential
                    {
                        Id = id,
                        Key = key,
                        Algorithm = "HMACSHA256",
                        User = id
                    };
                }

                return null;
            };

            return credentials;
        }
    }
}
