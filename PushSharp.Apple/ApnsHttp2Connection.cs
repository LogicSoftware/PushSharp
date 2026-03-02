using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Net.Http;

namespace PushSharp.Apple
{
    public class ApnsHttp2Connection
    {
        static int ID = 0;

        public ApnsHttp2Connection (ApnsHttp2Configuration configuration)
        {
            id = ++ID;
            if (id >= int.MaxValue)
                ID = 0;

            Configuration = configuration;

            certificate = Configuration.Certificate;

            certificates = new X509CertificateCollection ();

            // Add local/machine certificate stores to our collection if requested
            if (Configuration.AddLocalAndMachineCertificateStores) {
                var store = new X509Store (StoreLocation.LocalMachine);
                certificates.AddRange (store.Certificates);

                store = new X509Store (StoreLocation.CurrentUser);
                certificates.AddRange (store.Certificates);
            }

            // Add optionally specified additional certs into our collection
            if (Configuration.AdditionalCertificates != null) {
                foreach (var addlCert in Configuration.AdditionalCertificates)
                    certificates.Add (addlCert);
            }

            // Finally, add the main private cert for authenticating to our collection
            if (certificate != null)
                certificates.Add (certificate);

            var handler = new WinHttpHandler();
            handler.ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            
            foreach (X509Certificate cert in certificates)
            {
                if (cert is X509Certificate2 cert2)
                    handler.ClientCertificates.Add(cert2);
            }

            httpClient = new HttpClient(handler);
        }

        public ApnsHttp2Configuration Configuration { get; private set; }

        X509CertificateCollection certificates;
        X509Certificate2 certificate;
        int id = 0;
        HttpClient httpClient;

        public async Task Send (ApnsHttp2Notification notification)
        {
            var url = string.Format ("https://{0}:{1}/3/device/{2}", 
                          Configuration.Host,
                          Configuration.Port,
                          notification.DeviceToken);

            var payload = notification.Payload.ToString ();

            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Version = new Version(2, 0);
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

            request.Headers.Add("apns-id", notification.Uuid);

            if((string.IsNullOrEmpty(notification.PushType)))
            {
                notification.PushType = "background";
            }
            request.Headers.Add("apns-push-type", notification.PushType);

            if (notification.Expiration.HasValue) {
                var sinceEpoch = notification.Expiration.Value.ToUniversalTime () - new DateTime (1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                var secondsSinceEpoch = (long)sinceEpoch.TotalSeconds;
                request.Headers.Add ("apns-expiration", secondsSinceEpoch.ToString ());
            }

            if (notification.Priority.HasValue)
                request.Headers.Add ("apns-priority", notification.Priority == ApnsPriority.Low ? "5" : "10");

            if (!string.IsNullOrEmpty (notification.Topic)) 
                request.Headers.Add ("apns-topic", notification.Topic);

            HttpResponseMessage response = await httpClient.SendAsync(request).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.OK) {
                if (response.Headers.Contains("apns-id"))
                {
                    var responseUuid = response.Headers.GetValues("apns-id").FirstOrDefault();
                    if (responseUuid != notification.Uuid)
                        throw new Exception ("Mismatched APNS-ID header values");
                }
            } else {
                var json = new JObject ();

                var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (!string.IsNullOrEmpty(responseBody)) {
                    json = JObject.Parse (responseBody);
                }
                
                var reason = json.Value<string> ("reason");

                if (response.StatusCode == HttpStatusCode.Gone || reason == "BadDeviceToken") {

                    var timestamp = DateTime.UtcNow;
                    if (json != null && json["timestamp"] != null) {
                        var sinceEpoch = json.Value<long> ("timestamp");
                        timestamp = new DateTime (1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds (sinceEpoch);
                    }

                    throw new PushSharp.Core.DeviceSubscriptionExpiredException (notification) {
                        OldSubscriptionId = notification.DeviceToken,
                        NewSubscriptionId = null,
                        ExpiredAt = timestamp
                    };
                }

                throw new Exception("Http2: " + reason);
            }
        }
    }
}

