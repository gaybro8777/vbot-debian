﻿using System;
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
using System.Threading;
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

        public string Url { get; set; }

        public string User { get; set; }

        public string Password { get; set; }

        public string Credentials { get; set; }

        public string ServerPublicKey { get; set; }

        public OSSIndexHttpClient(string api_version, string user, string password, string server_public_key = "")
        {
            this.ApiVersion = api_version;
            this.Url = string.Format("/v{0}/vulnerability/new", this.ApiVersion);
            this.User = user;
            this.Password = password;
            this.ServerPublicKey = "";
            this.Credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", this.User, this.Password)));
        }

        public bool AddVulnerability(OSSIndexVulnerability v)
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
                    //logger.Debug("Certificate details for host:\nIssuer: {0}\nSubject: {1}\nPublic key: {2}", certificate.Issuer, certificate.Subject, certificate.GetPublicKeyString());
                    return true;
                };
                HttpResponseMessage response = client.PostAsync(this.Url,
                  new StringContent(JsonConvert.SerializeObject(v), Encoding.UTF8, "application/json")).Result;
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }
                else
                {
                    logger.Info("Did not receive success status code from server. Server returned: {0}. Reason phrase: {1}", response.StatusCode, response.ReasonPhrase);
                    return false;
                }
            }
        }

        public async Task<bool> AddVulnerabilityAsync(OSSIndexVulnerability v)
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
                    //logger.Debug("Certificate details for host:\nIssuer: {0}\nSubject: {1}\nPublic key: {2}", certificate.Issuer, certificate.Subject, certificate.GetPublicKeyString());
                    return true;
                };
                HttpResponseMessage response = await client.PostAsync(this.Url,
                  new StringContent(JsonConvert.SerializeObject(v), Encoding.UTF8, "application/json"));
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }
                else
                {
                    logger.Info("Did not receive success status code from server. Server returned: {0}. Reason phrase: {1}", response.StatusCode, response.ReasonPhrase);
                    return false;
                }
            }
        }

        public List<Task<bool>> AddDebianPackageVulnerabilities(DebianPackage p)
        {
            List<Task<bool>> tasks = new List<Task<bool>>();
            tasks = p.MapToOSSIndexVulnerabilities().ToList().Select(v => Task<bool>.Factory.StartNew(() => this.AddVulnerability(v),
                CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Default)).ToList();
            return tasks;
        }

        public List<Tuple<OSSIndexVulnerability, Task<bool>>> AddVulnerabilities(List<OSSIndexVulnerability> vulnerabilities)
        {
            List<Tuple<OSSIndexVulnerability, Task<bool>>> add_tasks = new List<Tuple<OSSIndexVulnerability, Task<bool>>>(vulnerabilities.Count);  
            foreach(OSSIndexVulnerability v in vulnerabilities)
            {
                Tuple<OSSIndexVulnerability, Task<bool>> task = new Tuple<OSSIndexVulnerability, Task<bool>> 
                    (v, Task<bool>.Factory.StartNew(() => this.AddVulnerability(v),
                        CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Default));
                add_tasks.Add(task);
            }
                
            return add_tasks;
        }

        public List<Tuple<OSSIndexVulnerability, Task<bool>>> AddVulnerabilitiesAsync(List<OSSIndexVulnerability> vulnerabilities)
        {
            List<Tuple<OSSIndexVulnerability, Task<bool>>> add_tasks = new List<Tuple<OSSIndexVulnerability, Task<bool>>>(vulnerabilities.Count);
            foreach (OSSIndexVulnerability v in vulnerabilities)
            {
                Tuple<OSSIndexVulnerability, Task<bool>> task = new Tuple<OSSIndexVulnerability, Task<bool>>
                    (v, Task<bool>.Run(async () => await this.AddVulnerabilityAsync(v)));
                add_tasks.Add(task);
            }

            return add_tasks;
        }


    }
}
