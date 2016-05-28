using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NLog;

namespace vbot.core
{
    public class Configuration
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();
        public static Dictionary<string, string> ReadConfiguration()
        {
            string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"config");
            if (!File.Exists(file)) return null;
            Dictionary<string, string> config = new Dictionary<string, string>();
            try
            {
                using (FileStream fs = new FileStream(file, FileMode.Open))
                {
                    using (StreamReader sre = new StreamReader(fs))
                    {
                        while (!sre.EndOfStream)
                        {
                            string s = sre.ReadLine();
                            if (string.IsNullOrEmpty(s)) continue;
                            string[] c = s.Split(':');
                            if (c.Length != 2)
                            {
                                throw new Exception("Could not parse configuration file entry: " + s + ".");
                            }
                            else
                            {
                                config.Add(c[0], c[1]);
                            }
                        }

                    }
                }
                return config;
            }
            catch (IOException ioe)
            {
                logger.Error(ioe);
                throw;
            }
            catch (Exception e)
            {
                logger.Error(e);
                throw;
            }
        }

        public static void WriteConfiguration(Dictionary<string, string> config)
        {
            string file = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"config");
            try
            {
                using (FileStream fs = new FileStream(file, FileMode.Create))
                using (StreamWriter swe = new StreamWriter(fs))
                {
                    foreach (KeyValuePair<string, string> kv in config)
                    {
                        swe.WriteLine(kv.Key + ":" + kv.Value);
                    }
                    swe.Flush();
                }
                logger.Info("Wrote {0} values to configuration file.", config.Count);
            }
            catch (IOException ioe)
            {
                logger.Error(ioe);
                throw;
            }
            catch (Exception e)
            {
                logger.Error(e);
                throw;
            }
        }
    }
}
