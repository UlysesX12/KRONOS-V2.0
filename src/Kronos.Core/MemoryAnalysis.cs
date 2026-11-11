// Copyright (c) 2026 Jose Luis Cabanas (JLC / UlysesX12).
// Distribuido bajo Volatility Software License 1.0; vease LICENSE.md.
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace Kronos.Core;

public sealed class MemoryAnalysis
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string EvidenceId { get; set; } = "";
    public string RelativeDirectory { get; set; } = "";
    public DateTimeOffset StartedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? FinishedUtc { get; set; }
    public string Engine { get; set; } = "Volatility 3";
    public string EngineVersion { get; set; } = "";
    public string EntrySha256 { get; set; } = "";
    public string SourceSha256Before { get; set; } = "";
    public string SourceSha256After { get; set; } = "";
    public string Integrity { get; set; } = "NO VERIFICADA";
    public string Status { get; set; } = "EN CURSO";
    public string Error { get; set; } = "";
    public bool Offline { get; set; }
    public string OutputsManifestSha256 { get; set; } = "";
    public List<MemoryModule> Modules { get; set; } = [];
    public override string ToString() => $"{StartedUtc:yyyy-MM-dd HH:mm} UTC · {Status} · {Id[..Math.Min(Id.Length, 8)]}";
}

public sealed class MemoryModule
{
    public string Plugin { get; set; } = "";
    public string Name { get; set; } = "";
    public string Status { get; set; } = "PENDIENTE";
    public int? ExitCode { get; set; }
    public int Rows { get; set; }
    public string ResultsPath { get; set; } = "";
    public string LogPath { get; set; } = "";
    public string Error { get; set; } = "";
    public List<string> Arguments { get; set; } = [];
    public override string ToString() => $"{Name} · {Status} · {Rows} filas";
}

public sealed record MemoryRow(string JsonPointer, Dictionary<string, string> Cells);
public sealed record MemoryArtifact(string File, long Bytes, string Sha256);
public sealed record MemoryTable(List<string> Columns, List<MemoryRow> Rows, int TotalRows)
{
    public static MemoryTable Parse(string json, int maximumRows = 10000)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 128 });
        if (document.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Volatility no devolvió una tabla JSON.");
        var columns = new List<string>(); var rows = new List<MemoryRow>(); var total = 0;
        void Walk(JsonElement array, string pointer)
        {
            var index = 0;
            foreach (var element in array.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Fila de memoria inválida.");
                var location = $"{pointer}/{index++}";
                total++;
                var cells = new Dictionary<string, string>();
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Name == "__children") continue;
                    if (!columns.Contains(property.Name)) columns.Add(property.Name);
                    if (rows.Count < maximumRows) cells[property.Name] = property.Value.ValueKind == JsonValueKind.String
                        ? property.Value.GetString() ?? "" : property.Value.GetRawText();
                }
                if (rows.Count < maximumRows) rows.Add(new(location, cells));
                if (element.TryGetProperty("__children", out var children) && children.ValueKind == JsonValueKind.Array)
                    Walk(children, location + "/__children");
            }
        }
        Walk(document.RootElement, "");
        return new(columns, rows, total);
    }
}

public sealed record MemoryCommand(string Plugin, List<string> Arguments, string OutputFile, string LogFile, string WorkingDirectory);
public interface IMemoryRunner
{
    Task<string> GetVersionAsync(string directory, CancellationToken cancellation);
    Task<int> ExecuteAsync(MemoryCommand command, CancellationToken cancellation);
    string EntryPath { get; }
}

public sealed class VolatilityRunner(string python, string entryPath) : IMemoryRunner
{
    public const string RequiredVersion = "2.28.2";
    public string PythonExecutable => python;
    public string EntryPath { get; } = Path.GetFullPath(entryPath);
    public static VolatilityRunner Discover()
    {
        var directories = ResourceDirectories().ToList();
        var entry = FindResource("volatility_entry.py");
        var configured = Environment.GetEnvironmentVariable("KRONOS_MEMORY_PYTHON");
        var packaged = directories.Select(d => Path.Combine(d, "runtime", "python", "python.exe")).FirstOrDefault(File.Exists);
        var local = directories.Select(d => Path.Combine(d, ".tools", "memory", OperatingSystem.IsWindows() ? "Scripts/python.exe" : "bin/python")).FirstOrDefault(File.Exists);
        var executable = !string.IsNullOrWhiteSpace(configured) ? configured : packaged ?? local ??
            (File.Exists("/opt/kronos-memory/bin/python") ? "/opt/kronos-memory/bin/python" : OperatingSystem.IsWindows() ? "python" : "python3");
        return new(executable, entry);
    }
    private static IEnumerable<string> ResourceDirectories()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
        for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
            yield return directory.FullName;
    }
    public static string FindResource(string name) => ResourceDirectories().Select(d => Path.Combine(d, "engines", "memory", name)).FirstOrDefault(File.Exists)
        ?? throw new FileNotFoundException($"No se encuentra engines/memory/{name}. Conserva engines junto a KRONOS.");
    public static string LocalEnvironmentDirectory() => Path.Combine(ResourceDirectories().FirstOrDefault(d => File.Exists(Path.Combine(d, "global.json"))) ?? AppContext.BaseDirectory, ".tools", "memory");
    public async Task<string> GetVersionAsync(string directory, CancellationToken cancellation)
    {
        var output = Path.Combine(directory, "engine-version.txt");
        var log = Path.Combine(directory, "engine-version.log");
        var result = await ExecuteAsync(new("version", ["--kronos-version"], output, log, directory), cancellation);
        if (result != 0) throw new IOException("Motor RAM no disponible. Usa la publicación completa de KRONOS o reconstruye el Dev Container. " + ReadTail(log));
        var version = (await File.ReadAllTextAsync(output, cancellation)).Trim();
        if (version != RequiredVersion) throw new IOException($"Se necesita Volatility {RequiredVersion}; se encontró {version}. Prepara de nuevo el motor RAM.");
        return version;
    }
    public async Task<int> ExecuteAsync(MemoryCommand command, CancellationToken cancellation)
    {
        var info = new ProcessStartInfo(python) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = command.WorkingDirectory };
        info.ArgumentList.Add("-I"); info.ArgumentList.Add("-X"); info.ArgumentList.Add("utf8"); info.ArgumentList.Add(EntryPath);
        foreach (var arg in command.Arguments) info.ArgumentList.Add(arg);
        info.Environment["PYTHONUTF8"] = "1";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromMinutes(10));
        using var process = Process.Start(info) ?? throw new IOException("No se pudo iniciar el motor RAM.");
        await using var output = new FileStream(command.OutputFile, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        await using var error = new FileStream(command.LogFile, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        var stdout = process.StandardOutput.BaseStream.CopyToAsync(output);
        var stderr = process.StandardError.BaseStream.CopyToAsync(error);
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            if (!process.HasExited) process.Kill(true);
            await process.WaitForExitAsync(CancellationToken.None);
            await Task.WhenAll(stdout, stderr);
            cancellation.ThrowIfCancellationRequested();
            throw new TimeoutException("El módulo excedió el límite de 10 minutos. Se conservan los registros.");
        }
        await Task.WhenAll(stdout, stderr);
        return process.ExitCode;
    }
    public static string ReadTail(string file)
    {
        if (!File.Exists(file)) return "";
        using var stream = File.OpenRead(file);
        stream.Seek(Math.Max(0, stream.Length - 8192), SeekOrigin.Begin);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

public sealed partial class CaseService
{
    public string ResolveAnalysisPath(string relative)
    {
        var prefix = Path.GetFullPath(Path.Combine(Root, "analysis")) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(Path.Combine(Root, relative));
        if (!full.StartsWith(prefix, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new InvalidDataException("Ruta de análisis fuera del caso.");
        for (FileSystemInfo? item = new FileInfo(full); item is not null && item.FullName.Length >= Root.Length;
             item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent)
            if (item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidDataException("Enlace no permitido en el análisis.");
        return full;
    }
    public async Task<MemoryAnalysis> AnalyzeMemoryAsync(string evidenceId, IMemoryRunner runner, bool offline,
        IProgress<string>? progress = null, CancellationToken cancellation = default, bool extended = false)
    {
        cancellation.ThrowIfCancellationRequested();
        var evidence = Document.Evidence.Single(e => e.Id == evidenceId);
        var image = ResolveEvidence(evidence.RelativePath);
        var analysis = new MemoryAnalysis { EvidenceId = evidence.Id, Offline = offline };
        analysis.RelativeDirectory = $"analysis/memory_{analysis.Id}";
        var directory = ResolveAnalysisPath(analysis.RelativeDirectory);
        Directory.CreateDirectory(directory);
        Document.MemoryAnalyses.Add(analysis);
        await RecordAsync("Iniciar análisis RAM", $"{analysis.Id}; evidencia {evidence.Id}; solo lectura; Windows; offline={offline}");
        var cancelled = false;
        try
        {
            await using var guard = new FileStream(image, FileMode.Open, FileAccess.Read, FileShare.Read, 1048576, true);
            progress?.Report("Verificando la evidencia antes del análisis…");
            analysis.SourceSha256Before = Convert.ToHexString(await SHA256.HashDataAsync(guard, cancellation));
            if (analysis.SourceSha256Before != evidence.Sha256 || guard.Length != evidence.Size)
                throw new InvalidDataException("La copia de evidencia no coincide con su SHA-256 registrado. Análisis rechazado.");
            analysis.EntrySha256 = await HashAsync(runner.EntryPath, cancellation);
            analysis.EngineVersion = await runner.GetVersionAsync(directory, cancellation);
            var plugins = new List<(string, string)> { ("windows.info.Info", "Información del sistema"), ("windows.pslist.PsList", "Procesos"),
                ("windows.cmdline.CmdLine", "Líneas de comando"), ("windows.netscan.NetScan", "Conexiones de red") };
            if (extended) plugins.AddRange([
                ("windows.pstree.PsTree", "Árbol de procesos"), ("windows.psscan.PsScan", "Procesos por exploración"),
                ("windows.getsids.GetSIDs", "SID y cuentas de procesos"), ("windows.sessions.Sessions", "Sesiones"),
                ("windows.envars.Envars", "Variables de entorno"), ("windows.filescan.FileScan", "Archivos en memoria"),
                ("windows.registry.hivelist.HiveList", "Colmenas del registro"), ("windows.registry.userassist.UserAssist", "UserAssist"),
                ("windows.dlllist.DllList", "Bibliotecas de procesos"), ("windows.malware.malfind.Malfind", "Posible código inyectado (indicio)")]);
            analysis.Modules = plugins.Select(p => new MemoryModule { Plugin = p.Item1, Name = p.Item2,
                ResultsPath = analysis.RelativeDirectory + "/" + p.Item1 + ".json",
                LogPath = analysis.RelativeDirectory + "/" + p.Item1 + ".log" }).ToList();
            var cache = Path.Combine(Root, "analysis", "cache");
            var symbols = Path.Combine(Root, "analysis", "symbols");
            Directory.CreateDirectory(cache); Directory.CreateDirectory(symbols);
            foreach (var module in analysis.Modules)
            {
                cancellation.ThrowIfCancellationRequested();
                progress?.Report($"{module.Name}: ejecutando Volatility {analysis.EngineVersion}…");
                module.Status = "EN CURSO";
                module.Arguments = ["-q", "-r", "json", "--cache-path", cache, "-s", symbols, "-f", image,
                    "-o", directory, "--save-config", Path.Combine(directory, module.Plugin + ".config.json")];
                if (offline) module.Arguments.Add("--offline");
                module.Arguments.Add(module.Plugin);
                await SaveAsync();
                try
                {
                    module.ExitCode = await runner.ExecuteAsync(new(module.Plugin, module.Arguments,
                        ResolveAnalysisPath(module.ResultsPath), ResolveAnalysisPath(module.LogPath), directory), cancellation);
                    if (module.ExitCode != 0) throw new IOException($"Código {module.ExitCode}. " + VolatilityRunner.ReadTail(ResolveAnalysisPath(module.LogPath)));
                    var output = ResolveAnalysisPath(module.ResultsPath);
                    if (new FileInfo(output).Length > 128 * 1024 * 1024) throw new InvalidDataException("Salida JSON superior a 128 MiB; conservada en disco sin cargar en la interfaz.");
                    module.Rows = MemoryTable.Parse(await File.ReadAllTextAsync(output, cancellation), 0).TotalRows;
                    if (module.Plugin == "windows.info.Info" && module.Rows == 0) throw new InvalidDataException("El motor no devolvió información de un núcleo Windows compatible.");
                    module.Status = "CORRECTO";
                }
                catch (OperationCanceledException) { module.Status = "CANCELADO"; throw; }
                catch (Exception ex) { module.Status = "ERROR"; module.Error = ex.Message; }
                await SaveAsync();
                if (module.Plugin == "windows.info.Info" && module.Status != "CORRECTO") break;
            }
        }
        catch (OperationCanceledException) { cancelled = true; analysis.Error = "Análisis cancelado por el operador."; }
        catch (Exception ex) { analysis.Error = ex.Message; }
        finally
        {
            foreach (var module in analysis.Modules.Where(m => m.Status == "PENDIENTE")) module.Status = "NO EJECUTADO";
            progress?.Report("Verificando la evidencia al terminar y guardando resultados…");
            try
            {
                analysis.SourceSha256After = await HashAsync(image);
                analysis.Integrity = analysis.SourceSha256Before.Length == 0 ? "VERIFICACIÓN INCOMPLETA" :
                    analysis.SourceSha256Before == evidence.Sha256 && analysis.SourceSha256After == evidence.Sha256 ? "COINCIDE" : "DIFERENTE";
            }
            catch (Exception ex) { analysis.Integrity = "ERROR"; analysis.Error += " Verificación final: " + ex.Message; }
            var correct = analysis.Modules.Count(m => m.Status == "CORRECTO");
            analysis.Status = cancelled ? "CANCELADO" : analysis.Integrity != "COINCIDE" ? "FALLO DE INTEGRIDAD" :
                correct == 0 ? "ERROR" : correct == analysis.Modules.Count ? "COMPLETO" : "PARCIAL";
            analysis.FinishedUtc = DateTimeOffset.UtcNow;
            var manifest = new List<MemoryArtifact>();
            foreach (var file in Directory.EnumerateFiles(directory))
                manifest.Add(new(Path.GetFileName(file), new FileInfo(file).Length, await HashAsync(file)));
            var manifestPath = Path.Combine(directory, "outputs-manifest.json");
            await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifest, Json));
            analysis.OutputsManifestSha256 = await HashAsync(manifestPath);
            await File.WriteAllTextAsync(Path.Combine(directory, "summary.json"), JsonSerializer.Serialize(analysis, Json));
            await RecordAsync("Finalizar análisis RAM", $"{analysis.Id}: {analysis.Status}; integridad {analysis.Integrity}; {correct} módulos correctos; {analysis.Error}");
        }
        return analysis;
    }
    public async Task<MemoryTable> LoadMemoryTableAsync(MemoryAnalysis analysis, MemoryModule module)
    {
        if (!Document.MemoryAnalyses.Contains(analysis) || !analysis.Modules.Contains(module)) throw new InvalidDataException("Resultado ajeno al caso.");
        if (analysis.Integrity != "COINCIDE") throw new InvalidDataException("La integridad de la evidencia no está validada. Revisa las incidencias del análisis.");
        var directory = ResolveAnalysisPath(analysis.RelativeDirectory);
        var manifestFile = Path.Combine(directory, "outputs-manifest.json");
        if (await HashAsync(manifestFile) != analysis.OutputsManifestSha256) throw new InvalidDataException("El manifiesto de resultados ha cambiado.");
        var manifest = JsonSerializer.Deserialize<List<MemoryArtifact>>(await File.ReadAllTextAsync(manifestFile), Json) ?? [];
        var file = ResolveAnalysisPath(module.ResultsPath);
        if (Path.GetDirectoryName(file) != directory) throw new InvalidDataException("La tabla no pertenece al análisis.");
        var expected = manifest.Single(m => m.File == Path.GetFileName(file));
        if (new FileInfo(file).Length > 128 * 1024 * 1024) throw new InvalidDataException("Tabla demasiado grande para la vista previa; utiliza el JSON conservado.");
        var bytes = await File.ReadAllBytesAsync(file);
        if (bytes.Length != expected.Bytes || Convert.ToHexString(SHA256.HashData(bytes)) != expected.Sha256)
            throw new InvalidDataException("Los resultados JSON han cambiado respecto del manifiesto.");
        return MemoryTable.Parse(System.Text.Encoding.UTF8.GetString(bytes));
    }
}
