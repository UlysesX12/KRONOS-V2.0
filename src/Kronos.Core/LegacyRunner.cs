// Copyright (c) 2026 José Luis Cabañas (JLC / UlysesX12).
// Todos los derechos reservados sobre las aportaciones propias. Véase LICENSE.md.
using System.Diagnostics;
namespace Kronos.Core;

public static class LegacyRunner
{
    public static string VendorRoot => Path.Combine(AppContext.BaseDirectory, "vendor", "kronos-v1");
    public static async Task<string> RunAsync(string executable, IEnumerable<string> arguments, CancellationToken cancellation = default)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = VendorRoot };
        foreach (var arg in arguments) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new IOException("No se pudo iniciar el módulo.");
        var output = process.StandardOutput.ReadToEndAsync(cancellation);
        var error = process.StandardError.ReadToEndAsync(cancellation);
        try { await process.WaitForExitAsync(cancellation); }
        catch { if (!process.HasExited) process.Kill(true); throw; }
        var text = await output + "\n" + await error;
        if (process.ExitCode != 0) throw new IOException($"Módulo finalizó con código {process.ExitCode}: {text}");
        return text;
    }
}
