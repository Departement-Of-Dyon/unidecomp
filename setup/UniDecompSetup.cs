// UniDecomp Setup — installs unidecomp.exe and adds it to the user PATH.
// No Python required. Run: UniDecompSetup.exe
using System;
using System.IO;
using System.Reflection;
using Microsoft.Win32;

class UniDecompSetup
{
    static int Main()
    {
        try
        {
            string destDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Programs", "UniDecomp");
            Directory.CreateDirectory(destDir);

            // unidecomp.exe is embedded as a resource
            Assembly asm = Assembly.GetExecutingAssembly();
            Stream res = asm.GetManifestResourceStream("unidecomp.exe");
            FileStream beside = null;
            if (res == null)
            {
                string p = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "unidecomp.exe");
                if (File.Exists(p)) beside = File.OpenRead(p);
            }
            try
            {
                Stream input = res ?? (Stream)beside;
                if (input == null) { Console.WriteLine("error: unidecomp.exe payload not found"); return 1; }
                string dest = Path.Combine(destDir, "unidecomp.exe");
                using (FileStream fs = File.Create(dest)) input.CopyTo(fs);
                Console.WriteLine("installed: " + dest);
            }
            finally { if (beside != null) beside.Dispose(); if (res != null) res.Dispose(); }

            // add destDir to the USER PATH (registry — no admin needed)
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey("Environment", true))
            {
                string path = key.GetValue("Path", "") as string ?? "";
                var parts = new System.Collections.Generic.List<string>(path.Split(';'));
                bool found = false;
                foreach (var p in parts)
                    if (string.Equals(p.TrimEnd('\\'), destDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                        found = true;
                if (!found)
                {
                    parts.Add(destDir);
                    key.SetValue("Path", string.Join(";", parts), RegistryValueKind.ExpandString);
                    Console.WriteLine("added to user PATH: " + destDir);
                }
                else Console.WriteLine("already on PATH: " + destDir);
            }

            // notify the shell so new terminals pick up PATH immediately-ish
            try
            {
                IntPtr result;
                SendMessageTimeout(new IntPtr(0xFFFF), 0x1A, IntPtr.Zero, "Environment",
                    2, 5000, out result);
            }
            catch { }

            Console.WriteLine();
            Console.WriteLine("Done. Open a NEW terminal and run:");
            Console.WriteLine("    unidecomp <file>");
            Console.WriteLine("    unidecomp <file> --strings");
            Console.WriteLine("    unidecomp <file> --disasm");
            Console.WriteLine();
            Console.WriteLine("(current terminals won't see it until restarted)");
            Console.Write("Press Enter to exit...");
            Console.ReadLine();
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("install failed: " + ex.Message);
            Console.WriteLine(ex);
            Console.Write("Press Enter to exit...");
            Console.ReadLine();
            return 1;
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true,
        CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr wParam,
        string lParam, uint flags, uint timeout, out IntPtr result);
}
