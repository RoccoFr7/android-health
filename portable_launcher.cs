using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

internal static class PortableLauncher
{
    [STAThread]
    private static int Main(string[] args)
    {
        bool test = args.Length == 1 && args[0] == "--self-test";
        string directory = AppDomain.CurrentDomain.BaseDirectory;
        string runtime = Path.Combine(directory, "runtime");
        var start = new ProcessStartInfo {
            FileName = Path.Combine(runtime, test ? "python.exe" : "pythonw.exe"),
            Arguments = "-E -s -B " + (test ? "portable_self_test.py" : "gui.pyw"),
            WorkingDirectory = directory,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.EnvironmentVariables["TCL_LIBRARY"] = Path.Combine(runtime, @"tcl\tcl8.6");
        start.EnvironmentVariables["TK_LIBRARY"] = Path.Combine(runtime, @"tcl\tk8.6");
        try {
            using (var process = Process.Start(start)) {
                process.WaitForExit();
                if (!test && process.ExitCode != 0)
                    MessageBox.Show("Avvio non riuscito. Estrai l'intero archivio in una cartella scrivibile.",
                                    "Android Health", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return process.ExitCode;
            }
        } catch (Exception error) {
            if (!test)
                MessageBox.Show(error.Message, "Android Health", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
