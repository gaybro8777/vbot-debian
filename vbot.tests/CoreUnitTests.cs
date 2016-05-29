﻿using System;
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
        public FileInfo json_2 = new FileInfo("example.2.json");
    

        [Fact]
        public void CanParseDebianJson()
        {
            List<DebianPackage> packages_1 = DebianPackage.ParseDebianJsonFile(json_1);
            Assert.NotEmpty(packages_1);
            Assert.Equal(packages_1.Count, 1);
            Assert.Equal(packages_1.First().Name, "prototypejs");
            
        }

        [Fact]
        public void CanAddVulnerabilityToOSSIndex()
        {
            List<DebianPackage> packages = DebianPackage.ParseDebianJsonFile(json_1);
            List<OSSIndexVulnerability> vulns = packages.First().MapToOSSIndexVulnerabilities();
            vulns.ForEach(v => v.Url += "vbot_unit_test" + v.Url + "_" + DateTime.UtcNow.Ticks.ToString());
            OSSIndexHttpClient c = new OSSIndexHttpClient("1.1e", "debian@vorsecurity.com", "d8gh#beharry");
            Assert.True(c.AddVulnerability(packages.First().MapToOSSIndexVulnerabilities().First()));
        }

        [Fact]
        public void CanAddVulnerabilities()
        {
            List<DebianPackage> packages = DebianPackage.ParseDebianJsonFile(json_1);
            OSSIndexHttpClient c = new OSSIndexHttpClient("1.1e", "debian@vorsecurity.com", "d8gh#beharry");
           // c.AddVulnerabilities(packages.First().MapToOSSIndexVulnerabilities());
        }

        [Fact]
        public void CanPutPackageVulnerabilities()
        {
            List<DebianPackage> packages_2 = DebianPackage.ParseDebianJsonFile(json_2);
            List<OSSIndexVulnerability> vulns = packages_2.First().MapToOSSIndexVulnerabilities();
            vulns.ForEach(v => v.Url += "_" + DateTime.UtcNow.Ticks.ToString());
            Assert.True(Database.PutVulnerabilities(vulns));
            OSSIndexVulnerability o;
            vulns.ForEach(v => Assert.True(Database.GetVulnerability(v.Url, out o)));
        }


    }
}
