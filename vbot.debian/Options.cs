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

        [Option('u', "user", Required = true, HelpText = "Specifies the user for authenticating with the OSS Index server.")]
        public string File { get; set; }

        [Option('p', "password", Required = true, HelpText = "Specifies the password for authenticating with the OSS Index server.")]
        public string Password { get; set; }

        [Option('d', "debian-key", Required = false, HelpText = "Specifies the public key on the SSL certificate to expect from the Debian security tracker server.")]
        public string DebianKey { get; set; }

        [Option('f', "local-file", Required = false, HelpText = "Specifies a local file containing the Debian security tracker JSON dump.")]
        public string LocalFile { get; set; }

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
