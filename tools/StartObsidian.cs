using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows.Forms;

[assembly: AssemblyTitle("III85III OBSIDIAN")]
[assembly: AssemblyDescription("Launch the verified portable OBSIDIAN package")]
[assembly: AssemblyVersion("0.20.0.0")]
internal static class StartObsidian
{
    [STAThread]
    private static void Main()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        string folder = Path.Combine(root, "release", "OBSIDIAN_0.20.0_Windows-x64");
        string executable = Path.Combine(folder, "OBSIDIAN.exe");
        try
        {
            if (!File.Exists(executable) || !Directory.Exists(Path.Combine(folder, "_internal")))
                throw new FileNotFoundException("The complete OBSIDIAN portable package was not found beside this launcher. Keep the release folder and its _internal runtime together.");
            Process.Start(new ProcessStartInfo(executable) { WorkingDirectory = folder, UseShellExecute = true });
        }
        catch (Exception error)
        {
            MessageBox.Show(error.Message, "III85III OBSIDIAN", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
