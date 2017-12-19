using ACMESharp.ACME;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ACMESharp.Providers.QCloud
{
    public class QCloudDnsChallengeHandler : IChallengeHandler
    {
        public string SecretId { get; set; }
        public string SecretKey { get; set; }
        public string Line { get; set; }

        public bool IsDisposed { get; private set; }

        public void CleanUp(ChallengeHandlingContext ctx)
        {
            throw new NotSupportedException("provider does not support clean up");
        }

        public void Dispose()
        {
            IsDisposed = true;
        }

        public void Handle(ChallengeHandlingContext ctx)
        {
            DnsChallenge dnsChallenge = ctx.Challenge as DnsChallenge;

            var cns = new QCloudAPI_SDK.Module.Cns();
            cns.setConfig(new SortedDictionary<string, object>() { { "SecretId", SecretId }, { "SecretKey", SecretKey }, { "RequestMethod", "GET" } });

            var recordName = dnsChallenge.RecordName;
            var topAndSecondLevelName = new StringBuilder();
            var subDomainName = new StringBuilder();
            byte level = 0;
            for (int i = recordName.Length - 1; i >= 0; i--)
            {
                if (recordName[i] == '.' && level < 2)
                    level++;
                if (level < 2)
                    topAndSecondLevelName.Insert(0, recordName[i]);
                else
                    subDomainName.Insert(0, recordName[i]);
            }

            var recordListResponse = (JObject)JsonConvert.DeserializeObject(cns.Call("RecordList", new SortedDictionary<string, object>()
            {
                {"domain", topAndSecondLevelName },
                {"offset", 0 },
                {"length", 100 },
                {"subDomain", subDomainName },
                {"recordType", "TXT" },
            }));

            ThrowQCloudError(recordListResponse);

            var record = (JArray)recordListResponse["records"];

            if (record.Count == 1)
            {
                //If record already exist.
                var domainListResponse = (JObject)JsonConvert.DeserializeObject(cns.Call("DomainList", new SortedDictionary<string, object>()
                {
                    {"domain", topAndSecondLevelName },
                    {"recordId", (int)record[0]["id"] },
                    {"subDomain", subDomainName },
                    {"recordType", "TXT" },
                    {"recordLine", (string)record[0]["line"] },
                    {"value", dnsChallenge.RecordValue },
                }));
                ThrowQCloudError(domainListResponse);
                ctx.Out.WriteLine("Updated DNS record of type [TXT] with name [{0}]",
                        dnsChallenge.RecordName);
            }
            else if (record.Count == 0)
            {
                //If record does not exist.
                var domainListResponse = (JObject)JsonConvert.DeserializeObject(cns.Call("DomainList", new SortedDictionary<string, object>()
                {
                    {"domain", topAndSecondLevelName },
                    {"subDomain", subDomainName },
                    {"recordType", "TXT" },
                    {"recordLine", (string)record[0]["默认"] },
                    {"value", dnsChallenge.RecordValue },
                }));
                ThrowQCloudError(domainListResponse);
                ctx.Out.WriteLine("Created DNS record of type [TXT] with name [{0}]",
                        dnsChallenge.RecordName);
            }
            else
            {
                throw new InvalidOperationException("There should not be more than one DNS txt record for the name.");
            }
        }

        private static void ThrowQCloudError(JObject response)
        {
            if ((int)response["code"] != 0)
            {
                throw new QCloudCnsRequestException("Error requesting DNS data from QCloud CNS. " + response["message"].ToString());
            }

        }
    }
}
