using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Xml;
using System.Xml.Linq;
using System.Linq;
using System.Security;
using System.Security.Permissions;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using NLog;
using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace vbot.core
{
    public class OSSIndexHttpClient
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        public string ApiVersion { get; set; }

        public Uri Url { get; set; }

        public string User { get; set; }

        public string Password { get; set; }

        public string Credentials { get; set; }

        public string ServerPublicKey { get; set; }

        public OSSIndexHttpClient(string api_version, string user, string password, string server_public_key = "")
        {
            this.ApiVersion = api_version;
            this.Url = new Uri(string.Format("v{0}/vulnerability/new", this.ApiVersion));
            this.User = user;
            this.Password = password;
            this.ServerPublicKey = "";
            this.Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", this.User, this.Password)));
        }

        public Task AddVulnerabilities(List<OSSIndexVulnerability> v)
        {
            using (HttpClient client = new HttpClient())
            {
                client.BaseAddress = new Uri(@"https://ossindex.net/");
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("user-agent", "vbot");
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", this.Credentials);
                ServicePointManager.ServerCertificateValidationCallback += (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) =>
                {
                    logger.Debug("Certificate details for host:\nIssuer: {0}\nSubject: {1}\nPublic key: {2}", certificate.Issuer, certificate.Subject, certificate.GetPublicKeyString());
                    return true;
                };
            }
            return null;
        }
        
    }
}
