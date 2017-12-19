using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ACMESharp.ACME;
using ACMESharp.Ext;

namespace ACMESharp.Providers.QCloud
{
    [ChallengeHandlerProvider("qclouddns", ChallengeTypeKind.DNS, false, Description = "A QCloud dns provider for handling Challenges.", Label = "QCloud DNS Provider")]
    public class QCloudDnsChallengeHandlerProvider : IChallengeHandlerProvider
    {
        private static readonly ParameterDetail[] PARAMS =
        {
            new ParameterDetail(nameof(QCloudDnsChallengeHandler.SecretId), ParameterType.TEXT, true, false, "Secret ID"),
            new ParameterDetail(nameof(QCloudDnsChallengeHandler.SecretKey), ParameterType.TEXT, true, false, "Secret Key"),
            new ParameterDetail(nameof(QCloudDnsChallengeHandler.Line), ParameterType.TEXT, false, false, "Line", "记录的线路名称，如：\"默认\""),
        };

        public IEnumerable<ParameterDetail> DescribeParameters() => PARAMS;

        public IChallengeHandler GetHandler(Challenge c, IReadOnlyDictionary<string, object> initParams) => new QCloudDnsChallengeHandler();

        public bool IsSupported(Challenge c) => c is DnsChallenge;
    }
}
