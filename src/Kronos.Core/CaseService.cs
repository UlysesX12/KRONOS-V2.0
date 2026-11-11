// Copyright (c) 2026 José Luis Cabañas (JLC / UlysesX12).
// Distribuido bajo Volatility Software License 1.0. Véase LICENSE.md.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net;

namespace Kronos.Core;

public sealed class CaseDocument
{
    public int SchemaVersion { get; set; } = 1;
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? Id : Name;
    public string Operator { get; set; } = "";
    public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string TimeZone { get; set; } = TimeZoneInfo.Local.Id;
    public string Notes { get; set; } = "";
    public List<Evidence> Evidence { get; set; } = [];
    public List<Operation> Operations { get; set; } = [];
    public List<MemoryAnalysis> MemoryAnalyses { get; set; } = [];
}
public sealed record Evidence(string Id, string Source, string RelativePath, long Size, string Sha256,
    DateTimeOffset ImportedUtc, DateTimeOffset SourceModifiedUtc, string Method);
public sealed record Operation(DateTimeOffset Utc, string Action, string Detail);
public sealed record Verification(string EvidenceId, string Status, string Detail);

public sealed partial class CaseService : IDisposable
{
    public const string FileName = "case.kronos.json";
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    public string Root { get; }
    public CaseDocument Document { get; }
    private readonly FileStream caseLock;
    private CaseService(string root, CaseDocument document, FileStream caseLock) { Root = root; Document = document; this.caseLock = caseLock; }
    public void Dispose() => caseLock.Dispose();
    private static FileStream Lock(string root) => new(Path.Combine(root, ".kronos.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);

    public static async Task<CaseService> CreateAsync(string parent, string id, string operatorName)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Trim().Length > 120 || id.Any(char.IsControl))
            throw new ArgumentException("Indica un nombre de caso de 1 a 120 caracteres, sin saltos de línea.");
        var name = id.Trim();
        id = new string(name.Normalize(NormalizationForm.FormD).Where(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_').Take(48).ToArray());
        if (id.Length == 0) id = "CASO";
        if (string.IsNullOrWhiteSpace(operatorName)) throw new ArgumentException("Indica el nombre del analista forense.");
        var root = Path.Combine(Path.GetFullPath(parent), $"KRONOS_{id}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.Combine(root, "evidence"));
        Directory.CreateDirectory(Path.Combine(root, "reports"));
        var service = new CaseService(root, new() { Id = id, Name = name, Operator = operatorName.Trim() }, Lock(root));
        try { await service.RecordAsync("Crear caso", "KRONOS V2.0; fechas en UTC; zona local registrada."); }
        catch { service.Dispose(); throw; }
        return service;
    }
    public static async Task<CaseService> OpenAsync(string path)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetDirectoryName(full)!;
        var caseLock = Lock(root);
        try
        {
        var document = JsonSerializer.Deserialize<CaseDocument>(await File.ReadAllTextAsync(full), Json)
            ?? throw new InvalidDataException("Documento de caso vacío.");
        if (document.SchemaVersion != 1 || string.IsNullOrWhiteSpace(document.Id) || document.Evidence is null || document.Operations is null || document.MemoryAnalyses is null)
            throw new InvalidDataException("Formato de caso no compatible.");
        var result = new CaseService(root, document, caseLock);
        foreach (var evidence in document.Evidence) result.ResolveEvidence(evidence.RelativePath);
        foreach (var analysis in document.MemoryAnalyses) result.ResolveAnalysisPath(analysis.RelativeDirectory);
        return result;
        }
        catch { caseLock.Dispose(); throw; }
    }
    public async Task SaveAsync()
    {
        var temporary = Path.Combine(Root, $".{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(Document, Json), new UTF8Encoding(false));
            File.Move(temporary, Path.Combine(Root, FileName), true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public async Task RecordAsync(string action, string detail)
    {
        Document.Operations.Add(new(DateTimeOffset.UtcNow, action, detail));
        await SaveAsync();
    }
    public static async Task<string> HashAsync(string path, CancellationToken cancellation = default)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, true);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellation));
    }
    public async Task<Evidence> ImportAsync(string source, IProgress<string>? progress = null, CancellationToken cancellation = default)
    {
        source = Path.GetFullPath(source);
        var id = Guid.NewGuid().ToString("N");
        var relative = $"evidence/{id}.bin";
        var target = ResolveEvidence(relative);
        try
        {
            var info = new FileInfo(source);
            if (!info.Exists) throw new FileNotFoundException("No existe el archivo de origen.", source);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Seleccione un archivo regular, sin enlace simbólico.");
            var size = info.Length;
            var modified = info.LastWriteTimeUtc;
            progress?.Report("Calculando SHA-256 del origen…");
            var originalHash = await HashAsync(source, cancellation);
            progress?.Report("Copiando evidencia…");
            await using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 1048576, true))
            await using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1048576, true))
                await input.CopyToAsync(output, cancellation);
            progress?.Report("Verificando origen y copia…");
            var copyHash = await HashAsync(target, cancellation);
            var afterHash = await HashAsync(source, cancellation);
            info.Refresh();
            if (originalHash != copyHash || originalHash != afterHash || info.Length != size || info.LastWriteTimeUtc != modified)
                throw new IOException("El origen cambió durante la importación o la copia no coincide. Se ha descartado la copia.");
            var evidence = new Evidence(id, source, relative, size, copyHash, DateTimeOffset.UtcNow,
                new DateTimeOffset(modified, TimeSpan.Zero), "Copia de archivo; SHA-256 origen antes/después y copia coincidentes");
            Document.Evidence.Add(evidence);
            try { await RecordAsync("Importar evidencia", $"{id}: {source}; {size} bytes; SHA-256 {copyHash}"); }
            catch { Document.Evidence.Remove(evidence); throw; }
            return evidence;
        }
        catch (Exception ex)
        {
            if (File.Exists(target)) File.Delete(target);
            await RecordAsync("Error de importación", $"{source}: {ex.Message}");
            throw;
        }
    }
    public string ResolveEvidence(string relative)
    {
        var prefix = Path.GetFullPath(Path.Combine(Root, "evidence")) + Path.DirectorySeparatorChar;
        var path = Path.GetFullPath(Path.Combine(Root, relative));
        if (!path.StartsWith(prefix, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new InvalidDataException("Ruta de evidencia fuera de la carpeta evidence.");
        var current = new FileInfo(path) as FileSystemInfo;
        while (current is not null && current.FullName.Length >= Root.Length)
        {
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("No se admiten enlaces en la ruta de evidencia.");
            current = current is FileInfo file ? file.Directory : ((DirectoryInfo)current).Parent;
        }
        return path;
    }
    public async Task<List<Verification>> VerifyAsync(CancellationToken cancellation = default)
    {
        var results = new List<Verification>();
        foreach (var item in Document.Evidence)
        {
            cancellation.ThrowIfCancellationRequested();
            try
            {
                var path = ResolveEvidence(item.RelativePath);
                var hash = await HashAsync(path, cancellation);
                var valid = hash == item.Sha256 && new FileInfo(path).Length == item.Size;
                results.Add(new(item.Id, valid ? "COINCIDE" : "DIFERENTE", $"SHA-256 actual: {hash}"));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            { results.Add(new(item.Id, "ERROR", ex.Message)); }
        }
        var known = Document.Evidence.Select(e => ResolveEvidence(e.RelativePath)).ToHashSet(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        // Enumerar únicamente el directorio administrado, sin seguir enlaces.
        foreach (var file in Directory.EnumerateFileSystemEntries(Path.Combine(Root, "evidence")))
            if (!known.Contains(file)) results.Add(new(Path.GetFileName(file), "NO REGISTRADO", "Archivo ajeno al inventario."));
        await RecordAsync("Verificar copias", JsonSerializer.Serialize(results));
        return results;
    }
    public async Task<string> ExportReportAsync()
    {
        var text = new StringBuilder($"# Informe técnico — {Document.DisplayName}\n\nNombre del analista forense: {Document.Operator}\n\nCreación UTC: {Document.CreatedUtc:O}\n\nZona registrada: {Document.TimeZone}\n\nGenerado UTC: {DateTimeOffset.UtcNow:O}\n\n## Metodología y alcance\n\nKRONOS V2.0. Importación de archivos regulares mediante copia y comparación SHA-256 del origen antes/después y del destino. No se identifica el formato por extensión. La verificación posterior compara las copias con el registro del caso, que no constituye un sello ni una firma independiente.\n\n## Evidencias\n\n");
        foreach (var e in Document.Evidence)
            text.Append($"- ID: {e.Id}\n  Origen: {e.Source}\n  Copia: {e.RelativePath}\n  Bytes: {e.Size}\n  SHA-256: {e.Sha256}\n  Importación UTC: {e.ImportedUtc:O}\n  Método: {e.Method}\n\n");
        text.AppendLine("## Análisis de memoria RAM\n");
        if (Document.MemoryAnalyses.Count == 0) text.AppendLine("No se ha ejecutado ningún análisis RAM en este caso.\n");
        foreach (var a in Document.MemoryAnalyses)
        {
            text.AppendLine($"- Análisis {a.Id}; evidencia {a.EvidenceId}; {a.Engine} {a.EngineVersion}; estado {a.Status}; integridad {a.Integrity}.\n  Inicio UTC: {a.StartedUtc:O}; fin UTC: {a.FinishedUtc:O}; offline: {a.Offline}.\n  SHA-256 previo: {a.SourceSha256Before}\n  SHA-256 posterior: {a.SourceSha256After}\n  Entrada del motor SHA-256: {a.EntrySha256}\n  Directorio: {a.RelativeDirectory}\n  Manifiesto de salidas SHA-256: {a.OutputsManifestSha256}\n  Incidencias: {a.Error}");
            foreach (var module in a.Modules) text.AppendLine($"  - {module.Name} ({module.Plugin}): {module.Status}, {module.Rows} filas, código {module.ExitCode}; fuente {module.ResultsPath}; registro {module.LogPath}; {module.Error}");
            text.AppendLine();
        }
        text.Append($"## Notas y conclusiones del profesional\n\n{Document.Notes}\n\n## Limitaciones\n\nRAM: módulos Windows de Volatility 3; el alcance depende de los símbolos y de cada módulo. No incluye análisis de imágenes de disco, extracción móvil ni descifrado. Los registros RAM no acreditan por sí solos autoría ni actividad actual. Los módulos de artefactos tienen su propia cobertura y limitaciones. Las coincidencias no atribuyen autoría. Revisar metodología, fuentes y conclusiones antes de emitir un dictamen.\n\n## Operaciones e incidencias\n\n");
        foreach (var op in Document.Operations) text.AppendLine($"- {op.Utc:O} | {op.Action} | {op.Detail}");
        var stem = Path.Combine(Root, "reports", $"informe_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path.GetDirectoryName(stem)!);
        await File.WriteAllTextAsync(stem + ".md", text.ToString(), Encoding.UTF8);
        await File.WriteAllTextAsync(stem + ".html", "<!doctype html><html lang=\"es\"><meta charset=\"utf-8\"><title>Informe KRONOS</title><style>body{max-width:1000px;margin:40px auto;font:15px system-ui}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><pre>" + WebUtility.HtmlEncode(text.ToString()) + "</pre></html>", Encoding.UTF8);
        await RecordAsync("Exportar informe", stem + ".md / .html; borrador editable");
        return stem + ".html";
    }
}
