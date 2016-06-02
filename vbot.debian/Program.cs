using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

using NLog;
using CommandLine;

using vbot.core;

namespace vbot.debian
{
    public enum ProgramExitStatus
    {
        Success = 0,
        InvalidArguments = 1,
        DownloadFailed = 2
    }

    internal class Program
    {
        #region Private fields
        private static Logger logger = LogManager.GetCurrentClassLogger();
        private static Dictionary<string, string> Config = null;
        private const string security_tracker_json_url = "https://security-tracker.debian.org/tracker/data/json";
        private const string test_debian_url = "http://cdimage.debian.org/debian-cd/8.4.0/amd64/iso-cd/debian-8.4.0-amd64-CD-1.iso";
        #endregion

        #region Public properties
        static Options ProgramOptions = new Options();
        public static string LastHash { get; set; }
        #endregion

        #region Public methods
        static int Main(string[] args)
        {
            if (!CommandLine.Parser.Default.ParseArguments(args, ProgramOptions))
            {
                return (int) ProgramExitStatus.InvalidArguments;
            }
            else
            {
                if (!string.IsNullOrEmpty(ProgramOptions.LocalFile))
                {
                    if (!File.Exists(ProgramOptions.LocalFile))
                    {
                        logger.Info("The local file {0} does not exist, exiting.", ProgramOptions.LocalFile);
                        return (int)ProgramExitStatus.InvalidArguments;
                    }
                }
                if (string.IsNullOrEmpty(ProgramOptions.User) || (string.IsNullOrEmpty(ProgramOptions.Password)))
                {
                    logger.Info("The user and password options must be specified.");
                    return (int)ProgramExitStatus.InvalidArguments;
                }
            }
            Config = core.Configuration.ReadConfiguration();
            if (Config == null)
            {
                logger.Info("No configuration present, creating with initial values.");
                Config = new Dictionary<string, string>()
                {
                    {"LastRun", "" },
                    { "LastHash", "" }
                };
                core.Configuration.WriteConfiguration(Config);
            }
            Configure();
            FileInfo f = null;
            if (string.IsNullOrEmpty(ProgramOptions.LocalFile))
            {
                if (!Directory.Exists("work")) Directory.CreateDirectory("work");
                f = new FileInfo(Path.Combine("work", DateTime.UtcNow.Ticks.ToString()));
                int percentage_completed = 0;
                long bytes_received = 0;
                DownloadProgressChangedEventHandler d = delegate (object sender, DownloadProgressChangedEventArgs e)
                {

                    if (e.ProgressPercentage > 0 && (e.ProgressPercentage - percentage_completed > 10))
                    {
                        logger.Debug("Received {0} KB, {1} percentage completed.", e.BytesReceived / 1024, e.ProgressPercentage);
                        percentage_completed = e.ProgressPercentage;
                    }
                    else
                    {
                        if ((e.BytesReceived - bytes_received) > 1024 * 1024)
                        {
                            bytes_received = e.BytesReceived;
                            logger.Debug("No progress percentage available, received {0} bytes.", bytes_received);
                        }
                    }
                };

                VBotHttpFileDownload vhfd = new VBotHttpFileDownload(security_tracker_json_url, f, d);
                logger.Debug("Downloading {0} to {1}...", vhfd.url.ToString(), f.Name);
                vhfd.StartTask().Wait();
                if (!vhfd.CompletedSuccessfully)
                {
                    logger.Info("The download of {0} did not complete successfully.");
                    if (vhfd.Error != null) logger.Error(vhfd.Error);
                    vhfd = null;
                    logger.Info("Nothing to do exiting.");
                    return (int)ProgramExitStatus.DownloadFailed;
                }
                vhfd = null;
                string hash = Cryptography.ComputeFileSHA1Hash(f);
                logger.Debug("Downloaded file SHA1 hash: {0}.", hash);
                if (hash == LastHash)
                {
                    logger.Info("File hash is the same as previous run: {0}. Nothing to do, exiting.", Program.LastHash);
                    return (int)ProgramExitStatus.Success;
                }
                else
                {
                    Config["LastHash"] = hash;
                    Program.LastHash = hash;
                    Configuration.WriteConfiguration(Config);
                }
            }
            else
            {
                f = new FileInfo(ProgramOptions.LocalFile);
            }
            List<DebianPackage> packages = DebianPackage.ParseDebianJsonFile(f);
            List<OSSIndexVulnerability> vulnerabilities = packages.SelectMany(p => p.MapToOSSIndexVulnerabilities()).ToList();
            logger.Info("{0} total vulnerabilities extracted.", vulnerabilities.Count);
            List<OSSIndexVulnerability> cached_vulnerabilities = new List<OSSIndexVulnerability>();
            foreach(OSSIndexVulnerability v in vulnerabilities)
            {
                OSSIndexVulnerability cached_v = null;
                if (Database.GetVulnerability(v.Url, out cached_v))
                {
                    if (v.EqualValues(cached_v))
                    {
                        cached_vulnerabilities.Add(v);
                    }
                }
            }
            vulnerabilities.RemoveAll(v => cached_vulnerabilities.Contains(v));
            logger.Info("{0} vulnerabilities are cached and have already been submitted to the OSS Index server.", cached_vulnerabilities.Count);
            OSSIndexHttpClient client = new OSSIndexHttpClient("1.1e", ProgramOptions.User, ProgramOptions.Password);
            if (!string.IsNullOrEmpty(ProgramOptions.PackageName))
            {
                vulnerabilities = vulnerabilities.Where(v => v.Name == ProgramOptions.PackageName).ToList();
                logger.Info("Found {0} new or updated vulnerabilities for package {1}.", vulnerabilities.Count, ProgramOptions.PackageName);
            }
            OSSIndexHttpClient c = new OSSIndexHttpClient("1.1e", ProgramOptions.User, ProgramOptions.Password);
            int i = 0;
            IEnumerable<IGrouping<int, OSSIndexVulnerability>> packages_vulnerabilities = vulnerabilities.GroupBy(x => i++ / 10).ToList();
            for (int g = 0; g < packages_vulnerabilities.Count(); g++)
            {
                List<Tuple<OSSIndexVulnerability, Task<bool>>> tasks = c.AddVulnerabilities(packages_vulnerabilities.Where(pv => pv.Key == g).SelectMany(s => s).ToList());
                while (tasks.Count > 0)
                {
                    Task.WaitAny(tasks.Select(t => t.Item2).ToArray());
                    List<Tuple<OSSIndexVulnerability, Task<bool>>> completed = tasks.Where(t => t.Item2.IsCompleted).ToList();
                    List<Tuple<OSSIndexVulnerability, Task<bool>>> faulted = tasks.Where(t => t.Item2.IsFaulted).ToList();
                    List<Tuple<OSSIndexVulnerability, Task<bool>>> cancelled = tasks.Where(t => t.Item2.IsCanceled).ToList();
                    Database.PutVulnerabilities(completed.Select(cv => cv.Item1).ToList());
                    completed.ForEach(cv => logger.Info("Added vulnerability with id {0} for package {1} to OSS Index and local database cache.", cv.Item1.Vid, cv.Item1.Name));
                    cancelled.ForEach(cv => logger.Info("The task to add vulnerability with id {0} for package {1} to OSS Index and local database cache.", cv.Item1.Vid, cv.Item1.Name));
                    faulted.ForEach(cv => logger.Info("The task to add vulnerability with id {0} for package {1} to OSS Index and local database cache.", cv.Item1.Vid, cv.Item1.Name));
                    tasks.RemoveAll(t => completed.Contains(t) || cancelled.Contains(t) || faulted.Contains(t));
                }
            }

            return (int)ProgramExitStatus.Success;
        }

        public static void Configure()
        {
            if (Config == null)
            {
                logger.Warn("Attempted to configure program with null Config object.");
                return;
            }
            else
            {
                if (Config.ContainsKey("LastHash")) Program.LastHash = (string)Config["LastHash"];
            }
        }

        public async static void AddVulnerabilitiesAsync(List<OSSIndexVulnerability> vulnerabilities)
        {
            int i = 0;
            IEnumerable<IGrouping<int, OSSIndexVulnerability>> packages_vulnerabilities = vulnerabilities.GroupBy(x => i++ / 10).ToList();
            OSSIndexHttpClient c = new OSSIndexHttpClient("1.1e", ProgramOptions.User, ProgramOptions.Password);
            for (int g = 0; g < packages_vulnerabilities.Count(); g++)
            {
                IEnumerable<OSSIndexVulnerability> task_vulnerabilities = packages_vulnerabilities.Where(pv => pv.Key == g).SelectMany(s => s); 
                {
                    List<Tuple<OSSIndexVulnerability, Task<bool>>> tasks = task_vulnerabilities.Select(tv =>
                    new Tuple<OSSIndexVulnerability, Task<bool>>(tv,
                        Task<bool>.Run(async () => await c.AddVulnerabilityAsync(tv)))).ToList();
                    while (tasks.Count > 0)
                    {
                        Task<bool> completed_task = await Task.WhenAny(tasks.Select(t => t.Item2).ToArray());
                        bool r = await completed_task;
                        List<Tuple<OSSIndexVulnerability, Task<bool>>> completed = tasks.Where(t => t.Item2.IsCompleted).ToList();
                        List<Tuple<OSSIndexVulnerability, Task<bool>>> faulted = tasks.Where(t => t.Item2.IsFaulted).ToList();
                        List<Tuple<OSSIndexVulnerability, Task<bool>>> cancelled = tasks.Where(t => t.Item2.IsCanceled).ToList();
                        Database.PutVulnerabilities(completed.Select(cv => cv.Item1).ToList());
                        completed.ForEach(cv => logger.Info("Added vulnerability with id {0} for package {1} to OSS Index and local database cache.", cv.Item2.Id, cv.Item1.Name));
                        cancelled.ForEach(cv => logger.Info("The task to add vulnerability with id {0} to OSS Index did not complete successfully.", cv.Item2.Id));
                        faulted.ForEach(cv => logger.Info("The task to add vulnerability with id {0} to OSS Index did not complete successfully.", cv.Item2.Id));
                        tasks.RemoveAll(t => t.Item2.IsCompleted || t.Item2.IsFaulted || t.Item2.IsCanceled);
                    }
                }
            }
        }
        #endregion

    }
}
