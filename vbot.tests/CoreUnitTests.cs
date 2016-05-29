using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Xunit;

using vbot.core;

namespace vbot.tests
{
    public class CoreUnitTests
    {
        public FileInfo json_1 = new FileInfo("example.1.json");
        public FileInfo json_2 = new FileInfo("example.1.json");
        [Fact]
        public void CanParseDebianJson()
        {
            List<DebianPackage> packages = DebianPackage.ParseDebianJsonFile(json_1);
            Assert.NotEmpty(packages);
        }

        [Fact]
        public void CanUploadVulnerability()
        {
            OSSIndexHttpClient c = new OSSIndexHttpClient("1.1e", "debian@vorsecurity.com", "debian@vorsecurity.com");
            
        }
    }
}
