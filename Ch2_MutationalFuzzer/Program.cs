using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Ch2_MutationalFuzzer
{
    public class Program
    {
        // fuzzer driver
        public static void Main(string[] args)
        {
            // GET: call get fuzzer
            _getFuzzer(args);
            Console.WriteLine();

            // POST: call post fuzzer
//            _postFuzzer(args);
        }

        //GET: fuzzer
        private static void _getFuzzer(string[] args)
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

        // POST: fuzzer
        private static void _postFuzzer(string[] args)
        {
            // Read request from the file
            string[] requestLines = File.ReadAllLines(args[0]);
            // Store request (line-by-line) in into a string array and grab the parameters from the last line
            string[] parms = requestLines[requestLines.Length - 1].Split('&');
            // host var: stores IP address of the host we are sending the request to
            string host = string.Empty;
            // Used to build the full request as a single string
            StringBuilder requestBuilder = new StringBuilder();

            foreach (string ln in requestLines)
            {
                if (ln.StartsWith("Host:"))
                    // Call Replace() on the string to remove the trailing \r 
                    host = ln.Split(' ')[1].Replace("\r", string.Empty);
                requestBuilder.Append(ln + "\n");
            }

            string request = requestBuilder + "\r\n";
            Console.WriteLine(request);

            // Begin fuzzing parameters for SQL injections 
            IPEndPoint rhost = new IPEndPoint(IPAddress.Parse(host), 80);
            foreach (string parm in parms)
            {
                using (Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    sock.Connect(rhost);

                    string val = parm.Split('=')[1];
                    string req = request.Replace("=" + val, "=" + val + "'");

                    byte[] reqBytes = Encoding.ASCII.GetBytes(req);
                    sock.Send(reqBytes);

                    byte[] buf = new byte[sock.ReceiveBufferSize];

                    sock.Receive(buf);
                    string response = Encoding.ASCII.GetString(buf);
                    if (response.Contains("error in your SQL syntax"))
                    {
                        Console.WriteLine("Parameter " + parm + " seems vulnerable");
                        Console.Write(" to SQL injection with value: " + val + "'");
                    }
                }
            }
        }
    }
}