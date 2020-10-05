using security_authorization_filter;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.Entity.Core.EntityClient;
using System.Data.SqlClient;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using Utils;
using System.Text.RegularExpressions;
using Microsoft.Rtc.Collaboration;
using Microsoft.Rtc.Signaling;
using UcmaMethods;
using System.Threading.Tasks;

namespace security_authorization_filter
{
    class TrustedApplicationServer
    {
        // admin configurable settings.
        private bool cDeviceAuthorization; // true: deny unauthorized devices; false: allow any devices.

        // Entity Framework connection string
        private EntityConnectionStringBuilder cEntity;

        // Application Event logging
        private AppEventLog cEventLog;
        private string cLogLevel;

        // UCMA
        private CollaborationPlatform cPlatform;
        private ApplicationEndpoint cAppEndpoint;

        public TrustedApplicationServer(EntityConnectionStringBuilder entity, AppEventLog log, string level)
        {
            // Application Event log.
            cEventLog = log;
            cLogLevel = level;

            // database connection entity.
            cEntity = entity;
        }

        internal async void Start()
        {
            string _userAgent = "Security Authorization Filter";
            string _applicationId = "urn:application:securityfilter";
            //string _applicationId = "urn:application:skypebot";
            ProvisionedApplicationPlatformSettings _settings = new ProvisionedApplicationPlatformSettings(_userAgent, _applicationId);
            cPlatform = new CollaborationPlatform(_settings);
            cPlatform.RegisterForApplicationEndpointSettings(OnApplicationEndpointDiscovered);

            try
            {
                await cPlatform.StartupAsync();
            }
            catch (InvalidOperationException ox)
            {
                System.Diagnostics.Trace.WriteLine("Start failed: " + ox);
            }
            catch (RealTimeException ex)
            {
                System.Diagnostics.Trace.WriteLine("Start failed: " + ex);
            }
        }

        internal async void Stop()
        {
            try
            {
                await cAppEndpoint.TerminateAsync();
                await cPlatform.ShutdownAsync();
            }
            catch (InvalidOperationException ox)
            {
                System.Diagnostics.Trace.WriteLine("Stop failed: " + ox);
            }
            catch (RealTimeException ex)
            {
                System.Diagnostics.Trace.WriteLine("Start failed: " + ex);
            }
        }

        private async void OnApplicationEndpointDiscovered(object sender, ApplicationEndpointSettingsDiscoveredEventArgs e)
        {
            // update bot's presence.
            e.ApplicationEndpointSettings.UseRegistration = true;
            e.ApplicationEndpointSettings.AutomaticPresencePublicationEnabled = true;
            e.ApplicationEndpointSettings.Presence.PresentityType = "automaton";

            cAppEndpoint = new ApplicationEndpoint(cPlatform, e.ApplicationEndpointSettings);

            try
            {
                // register for incoming IM calls.
                cAppEndpoint.RegisterForIncomingCall<InstantMessagingCall>(OnIncomingIMCallReceived);
                await cAppEndpoint.EstablishAsync();

                System.Diagnostics.Trace.WriteLine("Trusted Application endpoint established: " + cAppEndpoint.EndpointUri);

                // register for database notifications.
                CheckConfiguration();
                ChallengeUnregisteredDevice();
                System.Diagnostics.Trace.WriteLine("Registration complete");
            }
            catch (InvalidOperationException ox)
            {
                System.Diagnostics.Trace.WriteLine("Trusted Application endpoint failed: " + ox);
            }
            catch (RealTimeException ex)
            {
                System.Diagnostics.Trace.WriteLine("Trusted Application endpoint failed: " + ex);
            }
        }

        // Handle incoming calls for IMs.
        private async void OnIncomingIMCallReceived(object sender, CallReceivedEventArgs<InstantMessagingCall> e)
        {
            System.Diagnostics.Trace.WriteLine("OnIncomingIMCallReceived: " + e.RemoteParticipant.Uri);

            try
            {
                // accept incoming IM call.
                await e.Call.AcceptAsync();
                string _reply = VerifyCode(e.RemoteParticipant.Uri, e.ToastMessage.Message);

                await e.Call.Flow.SendInstantMessageAsync(_reply);

                e.Call.Flow.MessageReceived += new EventHandler<InstantMessageReceivedEventArgs>(FlowInstantMessageReceived);
            }
            catch (InvalidOperationException ox)
            {
                System.Diagnostics.Trace.WriteLine("Accepting IM failed: " + ox);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine("Accepting IM failed: " + ex);
            }
        }

        private async void FlowInstantMessageReceived(object sender, InstantMessageReceivedEventArgs e)
        {
            System.Diagnostics.Trace.WriteLine("InstantMessageReceived: " + e.Sender.Uri);
            // process request.
            string _reply = VerifyCode(e.Sender.Uri, e.TextBody);
            // send response.
            InstantMessagingFlow _flow = (InstantMessagingFlow)sender;
            await _flow.SendInstantMessageAsync(_reply);
        }

        internal string VerifyCode(string sipuri, string response)
        {
            string _response = "This registration code is invalid. Please try again.";

            // strip out "sip:" at the beginning of the SIP URI.
            string _sipuri = sipuri.Substring("sip:".Length);
            System.Diagnostics.Trace.WriteLine("response: " + _sipuri + " [" + response + "]");

            try
            {
                // read configuration settings from database table SecurityFilterSettings.
                using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
                {
                    // query all signed-in users login on from an unregistered mobile device.
                    var _unregisteredDevice = db.DeviceCodes.AsNoTracking().Where(p => p.SipUri == _sipuri).SingleOrDefault();

                    if(_unregisteredDevice != null && _unregisteredDevice.AccessCode == "ACTIVATED")
                    {
                        // device is registered.
                        _response = "Your mobile device is now registered.";
                    }
                }
            }
            catch(Exception ex)
            {
                System.Diagnostics.Trace.WriteLine ("Please correct the following issue and restart this service.\n\nDatabase: failed to connect to SQL instance or more than one entry exists in the SecurityFilterSettings table\n" + ex.InnerException.Message.ToString() );
            }

            return _response;
        }

        // read device authorization configuration from database.
        private bool CheckConfiguration()
        {
            string _sqlcmd = @"SELECT [EnforceDeviceAuthorization] from [dbo].[SecurityFilterSettings]";

            try
            {
                using (SqlConnection _connection = new SqlConnection(cEntity.ProviderConnectionString))
                {
                    // open connection.
                    _connection.Open();

                    using (SqlCommand _command = new SqlCommand(_sqlcmd, _connection))
                    {
                        SqlDependency _dependency = new SqlDependency(_command);
                        _dependency.OnChange += new OnChangeEventHandler(Configuration_SqlDependencyOnChange);

                        // execute a non-query to subscribe for updates
                        _command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine("SQL Server notification configuration failed [SecurityFilterSettings]\n" + ex.InnerException.Message.ToString());
                return false;
            }
            
            try
            {
                // read configuration settings from database table SecurityFilterSettings.
                using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
                {
                    var _config = db.SecurityFilterSettings.SingleOrDefault();

                    // update configuration settings entry.
                    cDeviceAuthorization = (bool)_config.EnforceDeviceAuthorization;
                }

                // output configuration.
                System.Diagnostics.Trace.WriteLine("enforce device authorization: " + cDeviceAuthorization.ToString());

                return true;
            }
            catch(Exception ex)
            {
                System.Diagnostics.Trace.WriteLine ("Please correct the following issue and restart this service.\n\nDatabase: failed to connect to SQL instance or more than one entry exists in the SecurityFilterSettings table\n" + ex.InnerException.Message.ToString() );
                return false;
            }
        }

        // device authorization configuration notification.
        private void Configuration_SqlDependencyOnChange(object sender, SqlNotificationEventArgs e)
        {
            if(e.Info == SqlNotificationInfo.Invalid)
            {
                System.Diagnostics.Trace.WriteLine("settings SqlDependency state [INVALID]");
            }

            SqlDependency _dependency = (SqlDependency)sender;
            _dependency.OnChange -= Configuration_SqlDependencyOnChange;

            CheckConfiguration();
        }

        // read device authorization configuration from database.
        private async void ChallengeUnregisteredDevice()
        {
            // only listen for notifications if device authorization setting is true.
            if (false == cDeviceAuthorization)
            {
                return;
            }

            // only get notifications if the PromptUser field is modified by the Security Web Filter.
            string _sqlcmd = @"SELECT [PromptUser] from [dbo].[DeviceCodes]";

            try
            {
                using (SqlConnection _connection = new SqlConnection(cEntity.ProviderConnectionString))
                {
                    // open connection.
                    _connection.Open();

                    using (SqlCommand _command = new SqlCommand(_sqlcmd, _connection))
                    {
                        SqlDependency _dependency = new SqlDependency(_command);
                        _dependency.OnChange += new OnChangeEventHandler(UnregisteredDevice_SqlDependencyOnChange);

                        // execute a non-query to subscribe for updates
                        _command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine("SQL Server notification configuration failed [SecurityFilterSettings]\n" + ex.InnerException.Message.ToString());
                return;
            }

            try
            {
                // read configuration settings from database table SecurityFilterSettings.
                using (var db = new SecurityFilterManagerEntities(cEntity.ToString()))
                {
                    // query all signed-in users login on from an unregistered mobile device.
                    var _unregisteredDevices = db.DeviceCodes.Where(p => p.PromptUser == true);

                    foreach(var _device in _unregisteredDevices)
                    {
                        System.Diagnostics.Trace.WriteLine(_device.Name + " <" + _device.SipUri + "> [" + _device.AccessCode + "]");

                        try
                        {
                            Conversation _conversation = new Conversation(cAppEndpoint);
                            InstantMessagingCall _call = new InstantMessagingCall(_conversation);
                            await _call.EstablishAsync("sip:" + _device.SipUri, null);
                            await _call.Flow.SendInstantMessageAsync("Please enter your registration code to authorize your Skype for Business Mobile device");
                            await _call.TerminateAsync();
                            System.Diagnostics.Trace.WriteLine("message sent to: " + _device.Name);
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Trace.WriteLine("Send IM failed: " + ex.Message);
                        }
                        finally
                        {
                            // reset prompt to false.
                            _device.PromptUser = false;
                        }
                    }

                    db.SaveChanges();
                }
            }
            catch(Exception ex)
            {
                System.Diagnostics.Trace.WriteLine ("Please correct the following issue and restart this service.\n\nDatabase: failed to connect to SQL instance or more than one entry exists in the SecurityFilterSettings table\n" + ex.InnerException.Message.ToString() );
                return;
            }
        }

        // unregistered mobile device login notification.
        private void UnregisteredDevice_SqlDependencyOnChange(object sender, SqlNotificationEventArgs e)
        {
            if(e.Info == SqlNotificationInfo.Invalid)
            {
                System.Diagnostics.Trace.WriteLine("unregistered device SqlDependency state [INVALID]");
            }

            SqlDependency _dependency = (SqlDependency)sender;
            _dependency.OnChange -= UnregisteredDevice_SqlDependencyOnChange;

            ChallengeUnregisteredDevice();
        }
    }
}
