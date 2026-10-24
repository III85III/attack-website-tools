using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("III85III MIRAGE SENTINEL")]
[assembly: AssemblyDescription("Launch the verified portable Sentinel package")]
[assembly: AssemblyVersion("0.19.0.0")]
internal static class StartSentinel
{
    [STAThread]
    private static void Main()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        string folder = Path.Combine(root, "release", "III85III_MIRAGE_SENTINEL_0.19.0_Windows-x64");
        string executable = Path.Combine(folder, "Qolam_Sentinel.exe");
        try
        {
            if (!File.Exists(executable) || !Directory.Exists(Path.Combine(folder, "_internal")))
                throw new FileNotFoundException("The complete Sentinel portable package was not found beside this launcher. Keep the release folder and its _internal runtime together.");
            Process.Start(new ProcessStartInfo(executable) { WorkingDirectory = folder, UseShellExecute = true });
        }
        catch (Exception error)
        {
            MessageBox.Show(error.Message, "III85III MIRAGE SENTINEL", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
