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
        #endregion

    }
}
