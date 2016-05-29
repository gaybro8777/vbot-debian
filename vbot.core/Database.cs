using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using NLog;
using LightningDB;

namespace vbot.core
{
    public class Database
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();
        public static LightningEnvironment Environment = new LightningEnvironment("db");

        public static bool PutVulnerabilities(List<OSSIndexVulnerability> vulnerabilities)
        {
            if (!Environment.IsOpened) Environment.Open(EnvironmentOpenFlags.None);
            using (LightningTransaction tx = Environment.BeginTransaction())
            using (LightningDatabase db = tx.OpenDatabase(null, new DatabaseConfiguration { Flags = DatabaseOpenFlags.Create }))
            {
                try
                {
                    foreach (OSSIndexVulnerability v in vulnerabilities)
                    {
                        /*
                        using (MemoryStream ms = new MemoryStream())
                        using (BsonWriter writer = new BsonWriter(ms))
                        {
                            JsonSerializer serializer = new JsonSerializer();
                            serializer.Serialize(writer, v);
                        }
                        */
                        tx.Put(db, Encoding.UTF8.GetBytes(v.Url), Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(v)));
                    }
                    tx.Commit();
                    return true;
                }
                catch (LightningException e)
                {
                    logger.Error("Exception thown attmepting to write vulnerabilities to database.");
                    logger.Error(e);
                    return false;
                }
            }
        }

        public static bool GetVulnerability(string url, out OSSIndexVulnerability v)
        {
            using (LightningTransaction tx = Environment.BeginTransaction(TransactionBeginFlags.ReadOnly))
            {
                LightningDatabase db = tx.OpenDatabase();
                byte[] ret = null;
                if (!tx.TryGet(db, Encoding.UTF8.GetBytes(url), out ret))
                {
                    v = null;
                    return false;
                }
                else
                {
                    v = JsonConvert.DeserializeObject<OSSIndexVulnerability>(Encoding.UTF8.GetString(ret));
                    return true;
                }
            }
        }
   
    }
}
