// Dimetrix.exe — маленький запускатор: стартует app\Dimetrix.ps1 без окна консоли.
// Сборка: build.ps1 (использует компилятор C#, встроенный в Windows).
using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Dimetrix")]
[assembly: System.Reflection.AssemblyProduct("Dimetrix")]
[assembly: System.Reflection.AssemblyDescription("Диагностика домашней сети")]
[assembly: System.Reflection.AssemblyVersion("1.0.0.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.0.0")]

static class Launcher
{
    [STAThread]
    static void Main()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(root, "app", "Dimetrix.ps1");
        if (!File.Exists(script))
        {
            MessageBox.Show("Не найден файл app\\Dimetrix.ps1.\nDimetrix.exe должен лежать рядом с папкой app.",
                "Dimetrix", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + script + "\"",
            WorkingDirectory = Path.Combine(root, "app"),
            UseShellExecute = false,
            CreateNoWindow = true
        };
        try { Process.Start(psi); }
        catch (Exception e)
        {
            MessageBox.Show("Не удалось запустить PowerShell:\n" + e.Message, "Dimetrix", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
