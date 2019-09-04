using System;
using System.IO;
using System.Net;

namespace Ch2_MutationalFuzzer
{
    internal static class Program
    {
        public static void Main(string[] args)
        {
            var url = args[0];
            var index = url.IndexOf("?", StringComparison.Ordinal);
            var parms = url.Remove(0, index + 1).Split('&');
            foreach (var parm in parms)
            {
                // cross site scripting test (xss tainted param)
                var xssUrl = url.Replace(parm, parm + "fd<xss>sa");
                // sql injection test (single apostrophe)
                var sqlUrl = url.Replace(parm, parm + "fd'sa");

                // Building HTTP requests
                var request = (HttpWebRequest) WebRequest.Create(sqlUrl);
                request.Method = "GET";
                string sqlresp;

                using (var rdr =
                    new StreamReader(request.GetResponse().GetResponseStream() ?? throw new NullReferenceException()))
                    sqlresp = rdr.ReadToEnd();

                request = (HttpWebRequest) WebRequest.Create(xssUrl);
                request.Method = "GET";
                string xssresp;

                using (var rdr =
                    new StreamReader(request.GetResponse().GetResponseStream() ?? throw new NullReferenceException()))
                    xssresp = rdr.ReadToEnd();

                if (xssresp.Contains("<xss>"))
                    Console.WriteLine("Possible XSS point found in parameter: " + parm);

                if (sqlresp.Contains("error in your SQL syntax"))
                    Console.WriteLine("SQL injection point found in parameter: " + parm);
            }
        }
    }
}