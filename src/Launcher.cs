// Dimetrix.exe — маленький запускатор: стартует app\Dimetrix.ps1 без окна консоли.
// Сборка: build.ps1 (использует компилятор C#, встроенный в Windows).
using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("Dimetrix")]
[assembly: System.Reflection.AssemblyProduct("Dimetrix")]
[assembly: System.Reflection.AssemblyDescription("Диагностика домашней сети")]
[assembly: System.Reflection.AssemblyVersion("1.0.1.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.0.1.0")]

static class Launcher
{
    [STAThread]
    static void Main()
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(root, "app", "Dimetrix.ps1");
        if (!File.Exists(script))
        {
            if (IsRunFromArchive(root))
                MessageBox.Show("Похоже, Dimetrix.exe открыт прямо из архива — так он не видит папку app.\n\n" +
                    "Сначала распакуйте архив: щёлкните по нему правой кнопкой мыши → «Извлечь всё…», " +
                    "затем откройте распакованную папку и запустите Dimetrix.exe оттуда.",
                    "Dimetrix — распакуйте архив", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else
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

    // При двойном щелчке по exe внутри архива Проводник, 7-Zip или WinRAR
    // извлекают только сам exe во временную папку — без папки app.
    static bool IsRunFromArchive(string dir)
    {
        string d = dir.ToLowerInvariant();
        if (d.Contains("\\appdata\\local\\temp\\") || d.Contains("\\temp1_") ||
            d.Contains("\\7zo") || d.Contains("\\rar$")) return true;
        try
        {
            string temp = Path.GetFullPath(Path.GetTempPath()).ToLowerInvariant();
            return Path.GetFullPath(dir).ToLowerInvariant().StartsWith(temp);
        }
        catch { return false; }
    }
}
