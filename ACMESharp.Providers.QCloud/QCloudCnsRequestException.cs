using System;
using System.Runtime.Serialization;

namespace ACMESharp.Providers.QCloud
{
    [Serializable]
    internal class QCloudCnsRequestException : Exception
    {
        public QCloudCnsRequestException()
        {
        }

        public QCloudCnsRequestException(string message) : base(message)
        {
        }

        public QCloudCnsRequestException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected QCloudCnsRequestException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}