using System.Threading.Tasks;
using Microsoft.Rtc.Collaboration;
using Microsoft.Rtc.Signaling;
 
namespace UcmaMethods
{
    public static class ExtensionMethods
    {
        public static Task StartupAsync(this CollaborationPlatform platform)
        {
            return Task.Factory.FromAsync(platform.BeginStartup, 
                platform.EndStartup, null);
        }
 
        public static Task ShutdownAsync
            (this CollaborationPlatform platform)
        {
            return Task.Factory.FromAsync(platform.BeginShutdown, 
                platform.EndShutdown, null);
        }
 
        public static Task<SipResponseData> EstablishAsync(this
            LocalEndpoint endpoint)
        {
            return Task<SipResponseData>.Factory.FromAsync(
                endpoint.BeginEstablish, 
                endpoint.EndEstablish, null);
        }
 
        public static Task TerminateAsync(this LocalEndpoint endpoint)
        {
            return Task.Factory.FromAsync(endpoint.BeginTerminate, 
                endpoint.EndTerminate, null);
        }
 
        public static Task<CallMessageData> AcceptAsync(this Call call)
        {
            return Task<CallMessageData>.Factory.FromAsync(call.BeginAccept, 
                call.EndAccept, null);
        }
 
        public static Task<CallMessageData> EstablishAsync(this Call call, 
            string destinationUri, CallEstablishOptions options)
        {
            return Task<CallMessageData>.Factory.FromAsync(
                call.BeginEstablish, call.EndEstablish, 
                destinationUri, options, null);
        }
 
        public static Task TerminateAsync(this Call call)
        {
            return Task.Factory.FromAsync(call.BeginTerminate, 
                call.EndTerminate, null);
        }
 
        public static Task<SendInstantMessageResult> 
            SendInstantMessageAsync(this InstantMessagingFlow flow, 
            string textBody)
        {
            return Task<SendInstantMessageResult>.Factory.FromAsync(
                flow.BeginSendInstantMessage, 
                flow.EndSendInstantMessage, textBody, null);
        }
    }
}
