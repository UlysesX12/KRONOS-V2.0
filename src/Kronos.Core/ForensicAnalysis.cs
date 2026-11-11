// Copyright 2026 José Luis Cabañas (JLC / UlysesX12). Volatility Software License 1.0.
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace Kronos.Core;

public sealed class ForensicAnalysis
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string EvidenceId { get; set; } = "";
    public string Tool { get; set; } = "";
    public string Version { get; set; } = "";
    public string ExecutableSha256 { get; set; } = "";
    public string AdapterSha256 { get; set; } = "";
    public string RelativeDirectory { get; set; } = "";
    public DateTimeOffset StartedUtc { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? FinishedUtc { get; set; }
    public string Status { get; set; } = "EN CURSO";
    public string Integrity { get; set; } = "NO VERIFICADA";
    public string SourceSha256Before { get; set; } = "";
    public string SourceSha256After { get; set; } = "";
    public string OutputsManifestSha256 { get; set; } = "";
    public string Coverage { get; set; } = "";
    public string Error { get; set; } = "";
    public int Rows { get; set; }
    public List<string> Arguments { get; set; } = [];
    public override string ToString() => $"{StartedUtc:yyyy-MM-dd HH:mm} UTC · {Tool} · {Status} · {Rows:N0} filas";
}

public sealed record ForensicTool(string Id, string Name, string Scope)
{
    public override string ToString() => Name;
    public static readonly ForensicTool[] Catalog = [
        new("disk", "Discos RAW · particiones y volúmenes", "Imagen de disco o volumen RAW: GPT/MBR y firmas NTFS, FAT, exFAT, ext, XFS, BitLocker y LUKS. No enumera archivos, reconstruye RAID ni descifra volúmenes."),
        new("foremost", "Foremost · recuperar imágenes y archivos", "Volcados RAM e imágenes sin compresión. Recuperación por firmas; archivos fragmentados pueden quedar incompletos."),
        new("floss", "FLOSS · cadenas de ejecutables", "Archivos PE compatibles, cadenas estáticas y descodificadas. No determina si un archivo es malicioso."),
        new("aleapp", "ALEAPP · extracción Android", "Extracciones de sistema de archivos Android en ZIP/TAR/TAR.GZ. Analiza una extracción existente; no adquiere ni desbloquea teléfonos."),
        new("ileapp", "iLEAPP · extracción iOS", "Extracciones de sistema de archivos iOS en ZIP/TAR/TAR.GZ. No adquiere ni descifra dispositivos o copias cifradas."),
        new("browser", "Navegadores · historial y búsquedas GitHub", "Base SQLite History / places.sqlite de Chromium, Firefox o Safari. Solo base principal; WAL y borrados pendientes."),
        new("zip", "ZIP · contenido y cifrado", "Inventario del directorio ZIP: nombres, tamaños, CRC, cifrado y rutas peligrosas. No abre ni ejecuta su contenido."),
        new("strings", "Cadenas · indicios con offsets", "ASCII y UTF-16LE de archivos o RAM. Hasta 100000 cadenas; una cadena no equivale a un historial confirmado.")
    ];
}

public sealed partial class CaseService
{
    private static IEnumerable<string> ToolRoots()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
            for (var dir = new DirectoryInfo(start); dir is not null; dir = dir.Parent)
                yield return dir.FullName;
    }
    private static string WorkerPath() => ToolRoots().Select(r => Path.Combine(r, "engines", "forensics", "worker.py"))
        .FirstOrDefault(File.Exists) ?? throw new FileNotFoundException("Falta el adaptador forense incluido con KRONOS.");

    private static async Task<(string Executable, string Version, string Hash)> FindTool(string id, CancellationToken cancellation)
    {
        var receipt = ToolRoots().SelectMany(r => new[] { Path.Combine(r, "runtime", "tools", "tools.json"), Path.Combine(r, ".tools", "forensic-tools", "tools.json") })
            .FirstOrDefault(File.Exists) ?? throw new FileNotFoundException("Falta el paquete de herramientas forenses. Prepara la publicación con scripts/package-forensics.py.");
        using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(receipt, cancellation));
        var tool = doc.RootElement.EnumerateArray().Single(t => t.GetProperty("id").GetString() == id);
        var root = Path.GetDirectoryName(receipt)!;
        var executable = Path.GetFullPath(Path.Combine(root, tool.GetProperty("executable").GetString()!));
        if (!executable.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Ruta de herramienta inválida.");
        var hash = await HashAsync(executable, cancellation);
        if (!hash.Equals(tool.GetProperty("sha256").GetString(), StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("La herramienta no coincide con el manifiesto del paquete.");
        return (executable, tool.GetProperty("version").GetString()!, hash);
    }

    // Redirect into persistent files: tool output never fills UI memory. Kill entire process tree on cancel/timeout/budget.
    private static async Task<int> RunForensicProcess(string executable, IEnumerable<string> args, string directory, string label, CancellationToken cancellation)
    {
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = directory,
            RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        start.Environment["FLOSS_LOAD_VIV_WORKSPACE"] = "0";
        start.Environment["FLOSS_SAVE_WORKSPACE"] = "0";
        start.Environment["PYTHONUTF8"] = "1";
        using var process = Process.Start(start) ?? throw new IOException("No se pudo iniciar el motor forense.");
        process.StandardInput.Close();
        await using var stdout = File.Create(Path.Combine(directory, label + ".stdout.json"));
        await using var stderr = File.Create(Path.Combine(directory, label + ".stderr.log"));
        var copying = Task.WhenAll(process.StandardOutput.BaseStream.CopyToAsync(stdout), process.StandardError.BaseStream.CopyToAsync(stderr));
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        limit.CancelAfter(TimeSpan.FromMinutes(30));
        var finished = process.WaitForExitAsync(limit.Token);
        try
        {
            while (!finished.IsCompleted)
            {
                await Task.WhenAny(finished, Task.Delay(1500, limit.Token));
                limit.Token.ThrowIfCancellationRequested();
                long size = 0; var count = 0;
                foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
                {
                    if (++count > 100000 || (size += new FileInfo(file).Length) > 10L * 1024 * 1024 * 1024)
                        throw new IOException("Límite de salida alcanzado (10 GiB / 100000 archivos); resultados parciales conservados.");
                }
            }
            await finished;
            await copying;
            return process.ExitCode;
        }
        catch
        {
            if (!process.HasExited) process.Kill(true);
            await process.WaitForExitAsync();
            await copying;
            cancellation.ThrowIfCancellationRequested();
            if (limit.IsCancellationRequested) throw new TimeoutException("Límite de 30 minutos alcanzado; registros conservados.");
            throw;
        }
    }

    private static async Task TransferMobileOutput(string staging, string destination)
    {
        // Directory.Move cannot cross volumes (TEMP is commonly C:, cases may live on F:).
        if (Path.GetPathRoot(staging)!.Equals(Path.GetPathRoot(destination), StringComparison.OrdinalIgnoreCase))
        { Directory.Move(staging, destination); return; }
        var directories = new List<string> { staging };
        for (var index = 0; index < directories.Count; index++)
        {
            var source = directories[index];
            if ((File.GetAttributes(source) & FileAttributes.ReparsePoint) != 0) throw new IOException("Enlace no permitido en la salida móvil.");
            var target = Path.Combine(destination, Path.GetRelativePath(staging, source));
            Directory.CreateDirectory(target);
            foreach (var child in Directory.EnumerateDirectories(source)) directories.Add(child);
            foreach (var file in Directory.EnumerateFiles(source))
            {
                if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("Enlace no permitido en la salida móvil.");
                var copy = Path.Combine(target, Path.GetFileName(file));
                File.Copy(file, copy, false);
                if (await HashAsync(file) != await HashAsync(copy)) throw new IOException("No coincide la copia de la salida móvil; se conserva el temporal: " + staging);
            }
        }
        // All destinations verified before removing the private temporary copies.
        foreach (var dir in directories.AsEnumerable().Reverse())
        {
            foreach (var file in Directory.EnumerateFiles(dir)) File.Delete(file);
            Directory.Delete(dir);
        }
    }

    public async Task<ForensicAnalysis> AnalyzeForensicAsync(string evidenceId, string toolId,
        IProgress<string>? progress = null, CancellationToken cancellation = default)
    {
        _ = ForensicTool.Catalog.Single(t => t.Id == toolId);
        cancellation.ThrowIfCancellationRequested();
        var evidence = Document.Evidence.Single(e => e.Id == evidenceId);
        var input = ResolveEvidence(evidence.RelativePath);
        var run = new ForensicAnalysis { EvidenceId = evidenceId, Tool = toolId };
        run.RelativeDirectory = $"analysis/forensics_{run.Id}";
        var directory = ResolveAnalysisPath(run.RelativeDirectory);
        Directory.CreateDirectory(directory);
        Document.ForensicAnalyses.Add(run);
        await RecordAsync("Iniciar análisis forense", $"{run.Id}; {toolId}; evidencia {evidenceId}");
        try
        {
            await using var guard = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 1048576, true);
            progress?.Report("Verificando evidencia y motor…");
            run.SourceSha256Before = Convert.ToHexString(await SHA256.HashDataAsync(guard, cancellation));
            if (guard.Length != evidence.Size || run.SourceSha256Before != evidence.Sha256) throw new InvalidDataException("La evidencia ha cambiado. No se ejecuta el análisis.");
            var worker = WorkerPath();
            run.AdapterSha256 = await HashAsync(worker, cancellation);
            var python = VolatilityRunner.Discover().PythonExecutable;
            var normalizedSource = input;
            if (toolId is "foremost" or "floss" or "aleapp" or "ileapp")
            {
                var tool = await FindTool(toolId, cancellation);
                run.Version = tool.Version; run.ExecutableSha256 = tool.Hash;
                var args = new List<string>();
                string? staging = null;
                if (toolId == "floss") args.AddRange(["-j", input]);
                else if (toolId == "foremost")
                {
                    normalizedSource = Path.Combine(directory, "recovered");
                    args.AddRange(["-t", "jpg,png,gif,pdf,zip,ole", "-i", input, "-o", normalizedSource]);
                }
                else
                {
                    // Explicit archive types: never raw device images or implicit neighbouring-image discovery.
                    var source = evidence.Source.ToLowerInvariant();
                    var type = source.EndsWith(".zip") ? "zip" : source.EndsWith(".tar") ? "tar" : source.EndsWith(".gz") || source.EndsWith(".tgz") ? "gz" :
                        throw new InvalidDataException("Para LEAPP importa una extracción ZIP, TAR o TAR.GZ de Android/iOS.");
                    // LEAPP's report generator still uses some non-extended Windows paths.
                    // A short private staging directory avoids MAX_PATH failures in deeply nested cases.
                    staging = Path.Combine(Path.GetTempPath(), "krn-" + run.Id[..12]);
                    Directory.CreateDirectory(staging);
                    var mobileOutput = Path.Combine(staging, "mobile");
                    Directory.CreateDirectory(mobileOutput);
                    normalizedSource = Path.Combine(directory, "mobile");
                    args.AddRange(["-t", type, "-i", input, "-o", mobileOutput, "--hash", "--custom_output_folder", "report"]);
                }
                run.Arguments = args;
                await SaveAsync();
                progress?.Report($"{toolId} {tool.Version}: analizando la copia del caso…");
                int exit;
                try { exit = await RunForensicProcess(tool.Executable, args, staging ?? directory, "raw", cancellation); }
                finally
                {
                    if (staging is not null)
                    {
                        foreach (var file in new[] { "raw.stdout.json", "raw.stderr.log" })
                            if (File.Exists(Path.Combine(staging, file))) File.Move(Path.Combine(staging, file), Path.Combine(directory, file));
                        try
                        {
                            if (Directory.Exists(Path.Combine(staging, "mobile"))) await TransferMobileOutput(Path.Combine(staging, "mobile"), normalizedSource);
                        }
                        catch (Exception ex) { throw new IOException("No se pudo transferir la salida móvil. Temporal conservado: " + staging + ". " + ex.Message, ex); }
                        if (!Directory.EnumerateFileSystemEntries(staging).Any()) Directory.Delete(staging);
                    }
                }
                if (exit != 0) throw new IOException($"{toolId}: código {exit}. {VolatilityRunner.ReadTail(Path.Combine(directory, "raw.stderr.log"))}");
                if (toolId == "floss") normalizedSource = Path.Combine(directory, "raw.stdout.json");
            }
            else { run.Version = "KRONOS adapters 1"; run.ExecutableSha256 = await HashAsync(python, cancellation); }
            progress?.Report("Preparando tablas y referencias de origen…");
            var resultFile = Path.Combine(directory, "results.json");
            var normalize = await RunForensicProcess(python, ["-I", "-X", "utf8", worker, toolId, normalizedSource, resultFile], directory, "adapter", cancellation);
            if (normalize != 0) throw new IOException("Adaptador: " + VolatilityRunner.ReadTail(Path.Combine(directory, "adapter.stderr.log")));
            if (new FileInfo(resultFile).Length > 128 * 1024 * 1024) throw new IOException("Tabla superior a 128 MiB; conservada en disco.");
            run.Rows = MemoryTable.Parse(await File.ReadAllTextAsync(resultFile, cancellation), 0).TotalRows;
            using var coverage = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(directory, "results.coverage.json"), cancellation));
            run.Coverage = coverage.RootElement.GetProperty("coverage").GetString()!;
            run.Status = toolId is "aleapp" or "ileapp" || coverage.RootElement.GetProperty("truncated").GetBoolean() ? "REVISAR COBERTURA" : "CORRECTO";
        }
        catch (OperationCanceledException) { run.Status = "CANCELADO"; run.Error = "Cancelado por el analista."; }
        catch (Exception ex) { run.Status = "ERROR"; run.Error = ex.Message; }
        finally
        {
            progress?.Report("Verificando evidencia y guardando manifiesto de resultados…");
            try
            {
                run.SourceSha256After = await HashAsync(input);
                run.Integrity = run.SourceSha256Before == evidence.Sha256 && run.SourceSha256After == evidence.Sha256 ? "COINCIDE" : "DIFERENTE";
                if (run.Integrity != "COINCIDE") run.Status = "FALLO DE INTEGRIDAD";
            }
            catch (Exception ex) { run.Integrity = "ERROR"; run.Status = "FALLO DE INTEGRIDAD"; run.Error += " " + ex.Message; }
            run.FinishedUtc = DateTimeOffset.UtcNow;
            var manifest = new List<MemoryArtifact>();
            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
            {
                ResolveAnalysisPath(Path.GetRelativePath(Root, file));
                manifest.Add(new(Path.GetRelativePath(directory, file).Replace('\\', '/'), new FileInfo(file).Length, await HashAsync(file)));
            }
            var manifestFile = Path.Combine(directory, "outputs-manifest.json");
            await File.WriteAllTextAsync(manifestFile, JsonSerializer.Serialize(manifest, Json));
            run.OutputsManifestSha256 = await HashAsync(manifestFile);
            await File.WriteAllTextAsync(Path.Combine(directory, "summary.json"), JsonSerializer.Serialize(run, Json));
            await RecordAsync("Finalizar análisis forense", $"{run.Tool}: {run.Status}; {run.Integrity}; {run.Rows} filas; {run.Error}");
        }
        return run;
    }

    private async Task<string> VerifyForensicOutput(ForensicAnalysis run, string relative)
    {
        if (!Document.ForensicAnalyses.Contains(run) || run.Integrity != "COINCIDE") throw new InvalidDataException("Análisis ajeno al caso o integridad no validada.");
        var directory = ResolveAnalysisPath(run.RelativeDirectory);
        var manifest = Path.Combine(directory, "outputs-manifest.json");
        if (await HashAsync(manifest) != run.OutputsManifestSha256) throw new InvalidDataException("El manifiesto de resultados ha cambiado.");
        var entries = JsonSerializer.Deserialize<List<MemoryArtifact>>(await File.ReadAllTextAsync(manifest), Json)!;
        var expected = entries.SingleOrDefault(e => e.File == relative) ?? throw new InvalidDataException("Archivo no incluido en el manifiesto.");
        var file = ResolveAnalysisPath(run.RelativeDirectory + "/" + relative);
        if (new FileInfo(file).Length != expected.Bytes || await HashAsync(file) != expected.Sha256) throw new InvalidDataException("El resultado ha cambiado.");
        return file;
    }
    public async Task<MemoryTable> LoadForensicTableAsync(ForensicAnalysis run)
    {
        var file = await VerifyForensicOutput(run, "results.json");
        if (new FileInfo(file).Length > 128 * 1024 * 1024) throw new InvalidDataException("Tabla demasiado grande para la vista previa.");
        return MemoryTable.Parse(await File.ReadAllTextAsync(file));
    }
    public async Task<Evidence> ImportRecoveredAsync(ForensicAnalysis run, string relative, CancellationToken cancellation = default)
    {
        if (run.Tool != "foremost" || !relative.StartsWith("recovered/", StringComparison.Ordinal)) throw new InvalidDataException("Selecciona un archivo recuperado por Foremost.");
        var file = await VerifyForensicOutput(run, relative);
        var evidence = await ImportAsync(file, cancellation: cancellation);
        var derived = evidence with { ParentEvidenceId = run.EvidenceId, DerivedFrom = run.Id + "/" + relative };
        Document.Evidence[Document.Evidence.IndexOf(evidence)] = derived;
        await RecordAsync("Importar evidencia derivada", $"{derived.Id}; origen {derived.DerivedFrom}; evidencia padre {derived.ParentEvidenceId}");
        return derived;
    }
}
