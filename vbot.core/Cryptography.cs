using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace vbot.core
{
    public class Cryptography
    {
        public static string ComputeFileSHA1Hash(FileInfo f)
        {
            if (!f.Exists) throw new Exception(f.FullName + " does not exist.");
            using (FileStream fs = new FileStream(f.FullName, FileMode.Open))
            using (SHA1CryptoServiceProvider p = new SHA1CryptoServiceProvider())
            {
                return BitConverter.ToString(p.ComputeHash(fs));
            }
        }
    }

}
