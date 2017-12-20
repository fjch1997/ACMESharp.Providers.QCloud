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
        public string Line { get; set; } = "默认";

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
            if (string.IsNullOrEmpty(SecretId))
                throw new ArgumentNullException(nameof(SecretId));
            if (string.IsNullOrEmpty(SecretKey))
                throw new ArgumentNullException(nameof(SecretKey));
            if (string.IsNullOrEmpty(Line))
                throw new ArgumentNullException(nameof(Line));

            DnsChallenge dnsChallenge = (DnsChallenge)ctx.Challenge;

            var cns = new QCloudAPI_SDK.Module.Cns();
            cns.setConfig(new SortedDictionary<string, object>(StringComparer.Ordinal) { { "SecretId", SecretId }, { "SecretKey", SecretKey }, { "RequestMethod", "GET" } });

            var recordName = dnsChallenge.RecordName;
            var topAndSecondLevelNameBuilder = new StringBuilder();
            var subDomainNameBuilder = new StringBuilder();
            byte level = 0;
            for (int i = recordName.Length - 1; i >= 0; i--)
            {
                if (recordName[i] == '.' && level < 2)
                    level++;
                if (level < 2)
                    topAndSecondLevelNameBuilder.Insert(0, recordName[i]);
                else
                    subDomainNameBuilder.Insert(0, recordName[i]);
            }
            var topAndSecondLevelName = topAndSecondLevelNameBuilder.ToString();
            var subDomainName = subDomainNameBuilder.ToString();
            subDomainName = subDomainName.Substring(0, subDomainName.Length - 1);
            ctx.Out.WriteLine("Getting domain information for " + recordName + '.');
            var recordListResponse = (JObject)JsonConvert.DeserializeObject(cns.Call("RecordList", new SortedDictionary<string, object>(StringComparer.Ordinal)
            {
                {"domain", topAndSecondLevelName },
                {"offset", 0 },
                {"length", 100 },
                {"subDomain", subDomainName },
                {"recordType", "TXT" },
            }));

            ThrowQCloudError(recordListResponse);

            var record = (JArray)recordListResponse["data"]["records"];

            ctx.Out.WriteLine(record.Count + " existing record for " + recordName + " is found.");

            if (record.Count == 1)
            {
                //If record already exist.
                ctx.Out.WriteLine("Adding new record " + subDomainName + " in domain " + topAndSecondLevelName + ".");
                var domainListResponse = (JObject)JsonConvert.DeserializeObject(cns.Call("RecordModify", new SortedDictionary<string, object>(StringComparer.Ordinal)
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
                ctx.Out.WriteLine("Updating record " + subDomainName + " in domain " + topAndSecondLevelName + ".");
                var domainListResponse = (JObject)JsonConvert.DeserializeObject(cns.Call("RecordCreate", new SortedDictionary<string, object>(StringComparer.Ordinal)
                {
                    {"domain", topAndSecondLevelName },
                    {"subDomain", subDomainName },
                    {"recordType", "TXT" },
                    {"recordLine", Line },
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
