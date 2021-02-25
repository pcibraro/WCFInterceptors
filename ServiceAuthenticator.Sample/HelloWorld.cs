﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using System.Threading.Tasks;

namespace ServiceAuthenticator.Sample
{
    [ServiceContract]
    public interface IHelloWorld
    {
        [OperationContract]
        [WebGet(UriTemplate = "hello")]
        string Hello();
    }

    public class HelloWorldService : IHelloWorld
    {
        public string Hello()
        {
            return "Hello " +
                OperationContext.Current.ServiceSecurityContext.PrimaryIdentity.Name;
        }
    }
}
