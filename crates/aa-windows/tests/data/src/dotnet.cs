// Fixture assembly: a version, a target framework, P/Invokes and an obfuscator marker type.
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

[assembly: AssemblyVersion("2.3.4.5")]
[assembly: AssemblyTitle("Fixture .NET program")]
[assembly: TargetFramework(".NETFramework,Version=v4.7.2", FrameworkDisplayName = ".NET Framework 4.7.2")]

namespace Fixture.Net
{
    static class Native
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, uint size, uint type, uint protect);

        [DllImport("user32", EntryPoint = "MessageBoxW", CharSet = CharSet.Unicode)]
        public static extern int Box(IntPtr owner, string text, string caption, uint type);
    }

    static class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 100)
            {
                Native.VirtualAllocEx(IntPtr.Zero, IntPtr.Zero, 0, 0, 0);
                Native.Box(IntPtr.Zero, "x", "y", 0);
            }
            Console.WriteLine(new Uri("https://example.invalid/").Host);
        }
    }
}

namespace Fixture.Net.Protection
{
    // The name alone is what the obfuscator heuristic looks for.
    sealed class ConfusedByAttribute : Attribute { }
}
