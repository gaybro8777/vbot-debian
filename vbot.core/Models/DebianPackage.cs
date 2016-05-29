using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NLog;
using Newtonsoft.Json;


namespace vbot.core
{
    public class DebianPackage : IJsonValue
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();

        [JsonIgnore]
        public string JsonType { get; } = "package";

        public class CVE : IJsonValue
        {
            public string Name { get; set; }

            [JsonIgnore]
            public string JsonType { get; } = "cve";

            public int Year { get; set; }

            [JsonProperty("scope")]
            public string Scope { get; set; }

            [JsonProperty("debianbug")]
            public int DebianBug { get; set; }

            [JsonProperty("description")]
            public string Description { get; set; }

            [JsonProperty("releases")]
            public List<Release> Releases { get; set; }
        }

        public class Release : IJsonValue
        {
            public string Name { get; set; }

            [JsonIgnore]
            public string JsonType { get; } = "release";

            [JsonProperty("status")]
            public string Status { get; set; }

            [JsonProperty("repository")]
            public List<Repository> Repositories { get; set; }

            [JsonProperty("urgency")]
            public string Urgency { get; set; }

            [JsonProperty("nodsa")]
            public string Nodsa { get; set; }

            [JsonProperty("fixed_version")]
            public string FixedVersion { get; set; }
        }

        public class Repository: IJsonValue
        {
            public string Name { get; set; }

            [JsonIgnore]
            public string JsonType { get; } = "repository";

            public string Version { get; set; }
        }

        public class JsonList<T> : List<T>, IJsonValue where T : IJsonValue, new()
        {
            T v = new T();
            public string Name { get; set; }
            public string JsonType
            {
                get
                {
                    return v.JsonType + "_list";
                }
            }
        }

        [JsonIgnore]
        public string Name { get; set; }

        public List<CVE> CVEs { get; set; }

        public static List<DebianPackage> ParseDebianJsonFile(FileInfo f)
        {
            List<DebianPackage> packages = null; ;
            Stack<IJsonValue> stack = new Stack<IJsonValue>(50);
            using (StreamReader sr = new StreamReader(f.FullName))
            using (JsonTextReader jr = new JsonTextReader(sr))
            {
                while (jr.Read())
                {
                    IJsonValue top;
                    switch (jr.TokenType)
                    {
                        case JsonToken.StartObject:
                            if (stack.Count == 0)
                            {
                                stack.Push(new JsonList<DebianPackage>());
                                break;
                            }
                            else
                            {
                                top = stack.Peek();
                            }            
                            if (top.JsonType == "package")
                            {
                                JsonList<CVE> c = new JsonList<CVE>();
                                DebianPackage p = (DebianPackage)top;
                                p.CVEs = (List<CVE>)c;
                                stack.Push(c);
                            }
                            break;
                        case JsonToken.PropertyName:
                            top = stack.Peek();
                            if (top.JsonType == "package_list")
                            {
                                JsonList<DebianPackage> pl = (JsonList<DebianPackage>)top;
                                DebianPackage p = new DebianPackage() { Name = (string)jr.Value };
                                pl.Add(p);
                                stack.Push(p);
                            }
                            else if (top.JsonType == "cve_list")
                            {
                                JsonList<CVE> cl = (JsonList<CVE>)top;
                                CVE c = new CVE() { Name = (string)jr.Value };
                                cl.Add(c);
                                stack.Push(c);
                            }
                            else if (top.JsonType == "cve")
                            {
                                CVE cve = (CVE)top;
                                switch ((string)jr.Value)
                                {
                                    case "scope":
                                        cve.Scope = jr.ReadAsString();

                                        break;
                                    case "debianbug":
                                        string s = jr.ReadAsString();
                                        int db;
                                        if (Int32.TryParse(s, out db))
                                        {
                                            cve.DebianBug = db;
                                        }
                                        else
                                        {
                                            logger.Warn("Could not parse debianbug property {0} for CVE {1} as int.", s, cve.Name);
                                        }
                                        break;
                                    case "description":
                                        cve.Description = jr.ReadAsString();
                                        break;
                                    case "releases":
                                        JsonList<Release> rl = new JsonList<Release>();
                                        cve.Releases = rl;
                                        stack.Push(rl);
                                        break;
                                }
                            }
                            else if (top.JsonType == "release_list")
                            {
                                JsonList<Release> rl = (JsonList<Release>)top;
                                Release r = new Release() { Name = (string)jr.Value };
                                rl.Add(r);
                                stack.Push(r);
                            }
                            else if (top.JsonType == "release")
                            {
                                Release release = (Release)top;
                                switch ((string)jr.Value)
                                {
                                    case "status":
                                        release.Status = jr.ReadAsString();
                                        break;
                                    case "urgency":
                                        release.Urgency = jr.ReadAsString();
                                        break;
                                    case "nodsa":
                                        release.Nodsa = jr.ReadAsString();
                                        break;
                                    case "fixed_version":
                                        release.FixedVersion = jr.ReadAsString();
                                        break;
                                    case "repositories":
                                        JsonList<Repository> rl = new JsonList<Repository>();
                                        release.Repositories = rl;
                                        stack.Push(rl);
                                        break;
                                }
                            }
                            else if (top.JsonType == "repository_list")
                            {
                                JsonList<Repository> rl = (JsonList<Repository>)top;
                                Repository repository = new Repository()
                                {
                                    Name = (string) jr.Value,
                                    Version = jr.ReadAsString()
                                };
                                rl.Add(repository);
                            }
                            break;
                        case JsonToken.EndObject:
                            top = stack.Peek();
                            if (top.JsonType == "cve" || top.JsonType == "release" || top.JsonType == "release_list"
                                || top.JsonType == "repository" || top.JsonType == "repository_list")
                            {
                                stack.Pop();
                                //logger.Debug("Popped object {0} with name {1} from stack.", top.JsonType, top.Name);
                            }
                            if (top.JsonType == "cve_list") 
                            {
                                stack.Pop();
                                DebianPackage package = (DebianPackage) stack.Pop(); //cve list end means package end too
                                logger.Info("Parsed {0} CVEs for package {1}.", package.CVEs.Count, package.Name);
                            }
                            break;
                        default:
                            Exception e = new Exception(string.Format
                                ("Unexpected Json token in stream: {0} at path {1}, file position {2} with value {3}.", jr.TokenType.ToString(), jr.Path, jr.LinePosition, jr.Value));
                            logger.Error(e);
                            throw e;
                    }
                }
            }
            packages = (List<DebianPackage>)stack.Pop();
            logger.Info("Parsed {0} packages, {1} CVEs.", packages.Count, packages.Sum(p => p.CVEs.Count));
            return (List<DebianPackage>) packages;
        }

        public List<OSSIndexVulnerability> MapToOSSIndexVulnerabilities()
        {
            List<OSSIndexVulnerability> v = new List<OSSIndexVulnerability>(this.CVEs.Count * this.CVEs.Sum(c => c.Releases.Count));
            foreach(DebianPackage.CVE cve in this.CVEs)
            {
                foreach(DebianPackage.Release release in cve.Releases)
                {
                    v.Add(new OSSIndexVulnerability
                    {
                        Action = "add+approve",
                        PackageManager = "dpkg",
                        Name = this.Name,
                        Url = cve.DebianBug == 0 ?
                            string.Format("https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={0}#{1}", cve.DebianBug, release.Name) :
                            string.Format("https://ossindex.net/dpkg/{0}/{1}/{2}", release.Name, this.Name, release.Name),
                        Group = release.Name,
                        Description = cve.Description,
                        Version = release.FixedVersion,
                        CVEs = new string[] {cve.Name},
                    });
                }
            }
            return v;
        }

    }
}
