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
                        tx.Put(db, Encoding.UTF8.GetBytes(string.IsNullOrEmpty(v.Vid) ? v.Url : v.Vid + "#" + v.Group), Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(v)));
                    }
                    tx.Commit();
                    logger.Debug("Committed {0} vulnerabilities to database.", vulnerabilities.Count);
                    return true;
                }
                catch (LightningException e)
                {
                    logger.Error("Exception thrown attempting to write vulnerabilities to database.");
                    logger.Error(e);
                    return false;
                }
            }
        }

        public static bool GetVulnerability(string id, out OSSIndexVulnerability v)
        {
            if (!Environment.IsOpened) Environment.Open(EnvironmentOpenFlags.None);
            using (LightningTransaction tx = Environment.BeginTransaction(TransactionBeginFlags.ReadOnly))
            {
                LightningDatabase db = tx.OpenDatabase();
                byte[] ret = null;
                if (!tx.TryGet(db, Encoding.UTF8.GetBytes(id), out ret))
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

        public static void PrintAllVulnerabilities()
        {
            if (!Environment.IsOpened) Environment.Open(EnvironmentOpenFlags.None);
            using (LightningTransaction tx = Environment.BeginTransaction(TransactionBeginFlags.ReadOnly))
            {
                LightningDatabase db = tx.OpenDatabase();
                using (LightningCursor cursor = tx.CreateCursor(db))
                {
                    foreach (KeyValuePair<byte[], byte[]> r in cursor)
                    {
                        string id = Encoding.UTF8.GetString(r.Key);
                        OSSIndexVulnerability v = JsonConvert.DeserializeObject<OSSIndexVulnerability>(Encoding.UTF8.GetString(r.Value));
                        logger.Info("Id: {0}), Package: {1}, CVEs: {2}", id, v.Name, string.Join(" ", v.CVEs));
                    }
                }
            }

        }
    }
}
