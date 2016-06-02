using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using CommandLine;

using CommandLine.Text;

namespace vbot.debian
{
    class Options
    {
        public Options()
        {

        }

        [Option('u', "user", Required = false, HelpText = "Specifies the user for authenticating with the OSS Index server.")]
        public string User { get; set; }

        [Option('p', "password", Required = false, HelpText = "Specifies the password for authenticating with the OSS Index server.")]
        public string Password { get; set; }

        [Option('d', "debian-key", Required = false, HelpText = "Specifies the public key on the SSL certificate to expect from the Debian security tracker server.")]
        public string DebianKey { get; set; }

        [Option('f', "local-file", Required = false, HelpText = "Specifies a local file containing the Debian security tracker JSON dump.")]
        public string LocalFile { get; set; }

        [Option('n', "package-name", Required = false, HelpText = "Specifies a particular package to view and send to the OSS Index server.")]
        public string PackageName { get; set; }

        [Option('m', "dump-db", Required = false, HelpText = "Specifies a particular package to view and send to the OSS Index server.")]
        public bool DumpDatabase { get; set; }

        [ParserState]
        public IParserState LastParserState { get; set; }

        [HelpVerbOption]
        public string GetUsage(string verb)
        {
            return HelpText.AutoBuild(this, verb);
        }

        [HelpOption]
        public string GetUsage()
        {
            return HelpText.AutoBuild(this,
              (HelpText current) => HelpText.DefaultParsingErrorsHandler(this, current));
        }
    }
}
