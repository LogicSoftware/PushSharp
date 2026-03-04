using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using PushSharp.Apple;
using Newtonsoft.Json.Linq;

namespace PushSharp.Tests
{
    [TestFixture]
    [Category ("Disabled")]
    public class ApnsRealTest
    {
        [Test]
        public void APNS_Send_Single ()
        {
            var succeeded = 0;
            var failed = 0;
            var attempted = 0;

            var config = new ApnsHttp2Configuration (ApnsHttp2Configuration.ApnsServerEnvironment.Production, FindByThumbprint("BB80CA965848CE009580C64317E592CDC9C29F3D"));
            var broker = new ApnsHttp2ServiceBroker (config);
            broker.OnNotificationFailed += (notification, exception) => {
                failed++;
            };
            broker.OnNotificationSucceeded += (notification) => {
                succeeded++;
            };
            broker.Start ();

            IEnumerable<string> deviceTokens =
            [
            ];
            foreach (var dt in deviceTokens) {
                attempted++;
                broker.QueueNotification (new ApnsHttp2Notification {
                    DeviceToken = dt,
                    Topic = "net.logicsoftware.easyprojects",
                    PushType = "alert",
                    Payload = JObject.Parse (
                        """
                        {
                          "aps": {
                            "content-available": 1,
                            "sound": "default",
                            "alert": {
                              "title": "Test title",
                              "loc-key": "Notification.TaskMessageAdded.Body",
                              "loc-args": [
                                "First Last",
                                "@Administrator message"
                              ]
                            }
                          },
                          "data": {
                            "Type": "TaskMessageAdded",
                            "FeedId": 5813066,
                            "TaskId": 3900,
                            "TaskName": "Task Name",
                            "MessageId": 5855812,
                            "MessageText": "@Administrator message",
                            "PostedByUserId": 112,
                            "PostedByUserName": "First Last"
                          }
                        }
                        """)
                });
            }

            broker.Stop ();

            Assert.AreEqual (attempted, succeeded);
            Assert.AreEqual (0, failed);
        }

        [Test]
        public void APNS_Feedback_Service ()
        {
            var config = new ApnsConfiguration (
                ApnsConfiguration.ApnsServerEnvironment.Sandbox, 
                Settings.Instance.ApnsCertificateFile, 
                Settings.Instance.ApnsCertificatePassword);
            
            var fbs = new FeedbackService (config);
            fbs.FeedbackReceived += (string deviceToken, DateTime timestamp) => {
                // Remove the deviceToken from your database
                // timestamp is the time the token was reported as expired
            };
            fbs.Check ();
        }
        
        private static X509Certificate2 FindByThumbprint(string thumbprint)
        {
            if (string.IsNullOrWhiteSpace(thumbprint))
            {
                throw new ArgumentNullException(nameof(thumbprint));
            }

            X509Store certStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            certStore.Open(OpenFlags.ReadOnly);

            try
            {
                X509Certificate2Collection certCollection = certStore.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    false);

                if (certCollection.Count > 0)
                {
                    return certCollection[0];
                }
                else
                {
                    throw new InvalidOperationException("Unable to find a certificate with thumbprint " + thumbprint);
                }
            }
            finally
            {
                certStore.Close();
            }
        }
    }
}

