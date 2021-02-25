using HawkNet;
using JMFamily.WCF.ServiceAuthenticator;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.ServiceModel.Description;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ServiceAuthenticator.Sample
{
    class Program
    {

        static void Main(string[] args)
        {
            ServiceAuthenticatorFactory factory = new ServiceAuthenticatorFactory();
            var host = factory.CreateHost(typeof(CustomerDataService),
                new Uri[] { new Uri("http://localhost:8090/CustomerOData") });

            var host2 = factory.CreateHost(typeof(HelloWorldService),
                new Uri[] { new Uri("http://localhost:8091/HelloService") });


            host.Open();
            host2.Open();

            foreach (ServiceEndpoint endpoint in host.Description.Endpoints)
            {
                Console.WriteLine("Listening at " + endpoint.Address.Uri.AbsoluteUri);
            }

            foreach (ServiceEndpoint endpoint in host2.Description.Endpoints)
            {
                Console.WriteLine("Listening at " + endpoint.Address.Uri.AbsoluteUri);
            }

            Thread.Sleep(1000);

            var credential = new HawkCredential
            {
                Id = "id",
                Key = ConfigurationManager.AppSettings["HawkKey"],
                Algorithm = "sha256",
                User = "steve"
            };

            MakeCallWithHawk(credential);
            
            MakeCallWithJwt(ConfigurationManager.AppSettings["TenantId"],
                ConfigurationManager.AppSettings["ClientId"],
                ConfigurationManager.AppSettings["ClientSecret"],
                ConfigurationManager.AppSettings["Scope"]);

            Console.WriteLine("Press a key to exit");
            Console.ReadLine();

        }

        static void MakeCallWithHawk(HawkCredential credential)
        {
            var requestUri = new Uri("http://localhost:8090/CustomerOData/Customers");

            var request = (HttpWebRequest)WebRequest.Create(requestUri);

            var hawk = Hawk.GetAuthorizationHeader("localhost:8090",
                "GET",
                requestUri,
                credential);

            request.Headers.Add("Authorization", "Hawk " + hawk);

            try
            {
                var response = (HttpWebResponse)request.GetResponse();

                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    var content = sr.ReadToEnd();

                    Console.WriteLine("Received " + content);
                }

                response.Close();

            }
            catch (WebException ex)
            {
                var response = ((HttpWebResponse)ex.Response);

                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    var content = sr.ReadToEnd();

                    Console.WriteLine("Received " + content);
                }

                response.Close();
            }


        }

        static void MakeCallWithJwt(string tenant, string clientId, string clientSecret, string scope)
        {

            var requestJwtUri = new Uri("https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token");

            var requestJwt = (HttpWebRequest)WebRequest.Create(requestJwtUri);

            var postData = "client_id=" + Uri.EscapeDataString(clientId);
            postData += "&client_secret=" + Uri.EscapeDataString(clientSecret);
            postData += "&scope=" + Uri.EscapeDataString(scope);
            postData += "&grant_type=" + Uri.EscapeDataString("client_credentials");
            var data = Encoding.ASCII.GetBytes(postData);

            requestJwt.Method = "POST";
            requestJwt.ContentType = "application/x-www-form-urlencoded";
            requestJwt.ContentLength = data.Length;

            using (var stream = requestJwt.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }

            var responseJwt = (HttpWebResponse)requestJwt.GetResponse();

            var responseJwtString = new StreamReader(responseJwt.GetResponseStream()).ReadToEnd();

            dynamic untypedResponse = JObject.Parse(responseJwtString);

            var accessToken = untypedResponse["access_token"].ToString();

            var requestUri = new Uri("http://localhost:8090/CustomerOData/Customers");

            var request = (HttpWebRequest)WebRequest.Create(requestUri);

            request.Headers.Add("Authorization", "Bearer " + accessToken);

            try
            {
                var response = (HttpWebResponse)request.GetResponse();

                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    var content = sr.ReadToEnd();

                    Console.WriteLine("Received " + content);
                }

                response.Close();

            }
            catch (WebException ex)
            {
                var response = ((HttpWebResponse)ex.Response);

                using (var sr = new StreamReader(response.GetResponseStream()))
                {
                    var content = sr.ReadToEnd();

                    Console.WriteLine("Received " + content);
                }

                response.Close();
            }


        }
    }
}
