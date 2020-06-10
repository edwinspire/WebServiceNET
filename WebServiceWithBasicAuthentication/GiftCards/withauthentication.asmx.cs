using System;
using System.Web;
using System.Text;
using System.Web.Services;
using System.Security.Principal;
using System.Net.Http.Headers;
using System.Threading;
using System.Web.Script.Services;
using Newtonsoft.Json;
using System.Diagnostics;

namespace WSTest
{


    public struct RespuestaWSTest {
        public string respuesta;
        public int codigo_respuesta;
    }


    [WebService(Description = "Web Service With Basic Autentication", Namespace = "prueba_ws.com")]
    public class WS : WebService
    {

        [WebMethod(Description = "Method With Basic Autentication")]
        [ScriptMethod(ResponseFormat = ResponseFormat.Json)]//Specify return format.
        public string Test(string string_test)
        {
            var r = new RespuestaWSTest { respuesta = string_test, codigo_respuesta = 1 };
            var json = JsonConvert.SerializeObject(r, Newtonsoft.Json.Formatting.Indented);
            return json;
        }

        private static void EventLogEntry(string message, EventLogEntryType type)
        {
            try
            {
                EventLog.WriteEntry("Application", message, type);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

    }

}

namespace WSTest.Modules { 

    public class BasicAuthHttpModule : IHttpModule
    {
        private const string Realm = "prueba_ws.com";

        private static  void EventLogEntry(string message, EventLogEntryType type) {
            try {
                EventLog.WriteEntry("Application", message, type);
            } catch (Exception e) {
                Console.WriteLine(e.Message);
            }
        }

        public void Init(HttpApplication context)
        {

            // Register event handlers
            context.AuthenticateRequest += OnApplicationAuthenticateRequest;
            context.EndRequest += OnApplicationEndRequest;
        }

        private static void SetPrincipal(IPrincipal principal)
        {
            Thread.CurrentPrincipal = principal;
            if (HttpContext.Current != null)
            {
                HttpContext.Current.User = principal;
            }
        }

        // TODO: Here is where you would validate the username and password.
        private bool CheckPassword(string username, string password)
        {
            
            var r = username == Properties.Settings.Default.WSUser && password == Properties.Settings.Default.WSPassword;
            EventLogEntry("Usuario " + username + " Password: " + password, EventLogEntryType.Information);
            return r;
        }

        private  void AuthenticateUser(string credentials)
        {
            try
            {
                var encoding = Encoding.GetEncoding("iso-8859-1");
                credentials = encoding.GetString(Convert.FromBase64String(credentials));

                int separator = credentials.IndexOf(':');
                string name = credentials.Substring(0, separator);
                string password = credentials.Substring(separator + 1);

                if (CheckPassword(name, password))
                {
                    var identity = new GenericIdentity(name);
                    SetPrincipal(new GenericPrincipal(identity, null));
                }
                else
                {
                    // Invalid username or password.
                    HttpContext.Current.Response.StatusCode = 401;
                }
            }
            catch (FormatException e)
            {
                // Credentials were not formatted correctly.
                EventLogEntry("FormatException " + e.Message, EventLogEntryType.Error);
                HttpContext.Current.Response.StatusCode = 401;
            }
        }

        private void OnApplicationAuthenticateRequest(object sender, EventArgs e)
        {
            var request = HttpContext.Current.Request;
            var authHeader = request.Headers["Authorization"];
            if (authHeader != null)
            {

                var authHeaderVal = AuthenticationHeaderValue.Parse(authHeader);
                //EventLogEntry("authHeader OK " + authHeaderVal.Scheme, EventLogEntryType.Information);
                // RFC 2617 sec 1.2, "scheme" name is case-insensitive
                if (authHeaderVal.Scheme.Equals("basic",
                        StringComparison.OrdinalIgnoreCase) &&
                    authHeaderVal.Parameter != null)
                {
                    AuthenticateUser(authHeaderVal.Parameter);
                }
            } 
            //else if (request.AppRelativeCurrentExecutionFilePath == "~/")
            //{
            //    EventLogEntry("Ingresa a la Raiz sin autenticar ", EventLogEntryType.Information);
            //    HttpContext.Current.Response.StatusCode = 200;
            //}
            else {
                //EventLogEntry("authHeader NULL ", EventLogEntryType.Error);
                HttpContext.Current.Response.StatusCode = 401;
            }
        }

        // If the request was unauthorized, add the WWW-Authenticate header 
        // to the response.
        private static void OnApplicationEndRequest(object sender, EventArgs e)
        {
            var response = HttpContext.Current.Response;

            //EventLogEntry("OnApplicationEndRequest " + response.StatusCode.ToString(), EventLogEntryType.Information);

            if (response.StatusCode == 401)
            {
                //response.Headers.Add("WWW-Authenticate",
                //string.Format("Basic realm=\"{0}\"", Realm));
                response.AddHeader("WWW-Authenticate",
                string.Format("Basic realm=\"{0}\"", Realm));
            }
        }

        public void Dispose()
        {
        }
    }
}