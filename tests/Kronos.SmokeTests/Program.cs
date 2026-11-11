// Copyright (c) 2026 José Luis Cabañas (JLC / UlysesX12).
// Todos los derechos reservados sobre las aportaciones propias. Véase LICENSE.md.
using Kronos.Core;
using System.Security.Cryptography;
using System.Text;

var parent = Path.Combine(Path.GetTempPath(), "kronos-synthetic-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(parent);
var passed = 0;
void Check(bool condition, string message) { if (!condition) throw new Exception(message); Console.WriteLine("OK " + message); passed++; }
try
{
    var source = Path.Combine(parent, "muestra.mem");
    await File.WriteAllTextAsync(source, "abc", new UTF8Encoding(false));
    var c = await CaseService.CreateAsync(parent, "TEST_001", "Operador sintético");
    var e = await c.ImportAsync(source);
    Check(e.Sha256 == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", "SHA-256 conocido y copia verificada");
    Check(await File.ReadAllTextAsync(source) == "abc", "Origen intacto");
    Check((await c.VerifyAsync()).Single().Status == "COINCIDE", "Verificación correcta");
    c.Document.Notes = "Conclusión editable <script>alert(1)</script>";
    await c.SaveAsync();
    try { using var duplicate = await CaseService.OpenAsync(Path.Combine(c.Root, CaseService.FileName)); throw new Exception("Permitió escritura concurrente"); }
    catch (IOException) { Check(true, "Bloquea apertura concurrente del caso"); }
    c.Dispose();
    using var reopened = await CaseService.OpenAsync(Path.Combine(c.Root, CaseService.FileName));
    c = reopened;
    Check(reopened.Document.Notes == c.Document.Notes && reopened.Document.Evidence.Count == 1, "Persistencia y reapertura");
    var report = await reopened.ExportReportAsync();
    Check((await File.ReadAllTextAsync(report)).Contains("&lt;script&gt;"), "HTML escapa texto de evidencia y notas");
    Check(File.Exists(Path.ChangeExtension(report, ".md")), "Informe Markdown editable");
    await File.WriteAllTextAsync(c.ResolveEvidence(e.RelativePath), "alterada");
    Check((await c.VerifyAsync()).Single().Status == "DIFERENTE", "Detecta copia alterada");
    File.Delete(c.ResolveEvidence(e.RelativePath));
    Check((await c.VerifyAsync()).Single().Status == "ERROR", "Detecta evidencia ausente");
    await File.WriteAllTextAsync(Path.Combine(c.Root, "evidence", "extra.bin"), "extra");
    Check((await c.VerifyAsync()).Any(v => v.Status == "NO REGISTRADO"), "Detecta archivo ajeno al inventario");
    try { c.ResolveEvidence("../fuera.bin"); throw new Exception("Escape permitido"); }
    catch (InvalidDataException) { Check(true, "Rechaza rutas fuera de evidence"); }
    try { await c.ImportAsync(Path.Combine(parent, "ausente")); throw new Exception("Importó ausente"); }
    catch (FileNotFoundException) { Check(c.Document.Evidence.Count == 1, "Archivo inexistente no crea evidencia"); }
    var cancellation = new CancellationToken(true);
    try { await c.ImportAsync(source, cancellation: cancellation); throw new Exception("Ignoró cancelación"); }
    catch (OperationCanceledException) { Check(c.Document.Evidence.Count == 1, "Cancelación no registra copia incompleta"); }
    Console.WriteLine($"{passed} comprobaciones superadas.");
}
finally { Directory.Delete(parent, true); }
