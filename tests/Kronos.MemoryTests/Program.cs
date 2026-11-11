// Copyright (c) 2026 Jose Luis Cabanas. Volatility Software License 1.0.
using Kronos.Core;

var root = Path.GetFullPath(Path.Combine(args.Contains("--forensics") ? ".tools" : Path.GetTempPath(), "kronos-memory-synthetic-" + Guid.NewGuid().ToString("N")));
Directory.CreateDirectory(root);
var checks = 0;
void Check(bool condition, string text) { if (!condition) throw new Exception(text); Console.WriteLine("OK " + text); checks++; }
try
{
    var image = Path.Combine(root, "synthetic.mem");
    await File.WriteAllBytesAsync(image, new byte[8192]);
    var entry = Path.Combine(root, "synthetic-runner.txt");
    await File.WriteAllTextAsync(entry, "SYNTHETIC TEST RUNNER, NOT REAL MEMORY DATA");
    using var c = await CaseService.CreateAsync(root, "SYNTHETIC", "Pruebas automáticas");
    var evidence = await c.ImportAsync(image);
    var engine = new SyntheticRunner(entry);
    var result = await c.AnalyzeMemoryAsync(evidence.Id, engine, true);
    Check(result.Status == "COMPLETO" && result.Integrity == "COINCIDE", "Orquesta los cuatro módulos y verifica SHA-256 antes/después");
    Check(result.Modules.Count == 4 && engine.Calls == 4, "Ejecuta cuatro módulos reales de la interfaz de integración (runner sintético)");
    var extended = await c.AnalyzeMemoryAsync(evidence.Id, new SyntheticRunner(entry), true, extended: true);
    Check(extended.Modules.Count == 14 && extended.Status == "COMPLETO" && extended.Modules.Any(m => m.Plugin == "windows.malware.malfind.Malfind"), "Perfil ampliado orquesta catorce módulos, incluidas sesiones y Malfind");
    var table = await c.LoadMemoryTableAsync(result, result.Modules[1]);
    Check(table.TotalRows == 2 && table.Rows[1].JsonPointer == "/0/__children/0", "Conserva filas anidadas y referencias JSON Pointer");
    Check(MemoryTable.Parse(SyntheticRunner.Rows, 1).Rows.Count == 1 && MemoryTable.Parse(SyntheticRunner.Rows, 1).TotalRows == 2, "Limita vista previa sin falsear el total");
    Check(result.Modules[3].Rows == 0 && result.Modules[3].Status == "CORRECTO", "Tabla vacía válida no se presenta como error");
    Check(File.Exists(c.ResolveAnalysisPath(result.RelativeDirectory + "/summary.json")), "Resumen y salidas persistentes fuera de evidence");
    await File.AppendAllTextAsync(c.ResolveAnalysisPath(result.Modules[1].ResultsPath), " ");
    try { await c.LoadMemoryTableAsync(result, result.Modules[1]); throw new Exception("Aceptó resultados manipulados"); }
    catch (InvalidDataException) { Check(true, "Detecta resultados JSON alterados antes de mostrarlos"); }
    var partial = await c.AnalyzeMemoryAsync(evidence.Id, new SyntheticRunner(entry, "network-error"), true);
    Check(partial.Status == "PARCIAL" && partial.Modules[3].ExitCode == 1, "Conserva resultados parciales y errores del módulo");
    var noInfoEngine = new SyntheticRunner(entry, "info-error");
    var noInfo = await c.AnalyzeMemoryAsync(evidence.Id, noInfoEngine, true);
    Check(noInfo.Status == "ERROR" && noInfoEngine.Calls == 1 && noInfo.Modules.Skip(1).All(m => m.Status == "NO EJECUTADO"), "Rechaza imagen incompatible y omite módulos dependientes");
    using var cancel = new CancellationTokenSource();
    var cancelRunner = new SyntheticRunner(entry, "cancel");
    var cancelTask = c.AnalyzeMemoryAsync(evidence.Id, cancelRunner, true, cancellation: cancel.Token);
    await cancelRunner.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
    cancel.Cancel();
    var cancelled = await cancelTask;
    Check(cancelled.Status == "CANCELADO" && cancelled.Integrity == "COINCIDE", "Cancelación conserva trazabilidad y verificación final");
    await File.WriteAllTextAsync(c.ResolveEvidence(evidence.RelativePath), "ALTERED SYNTHETIC EVIDENCE");
    var tamperEngine = new SyntheticRunner(entry);
    var altered = await c.AnalyzeMemoryAsync(evidence.Id, tamperEngine, true);
    Check(altered.Status == "FALLO DE INTEGRIDAD" && tamperEngine.Calls == 0, "No ejecuta motor sobre evidencia que cambió desde la importación");
    await File.WriteAllBytesAsync(c.ResolveEvidence(evidence.RelativePath), new byte[8192]);
    if (args.Contains("--real-engine"))
    {
        var real = await c.AnalyzeMemoryAsync(evidence.Id, VolatilityRunner.Discover(), true);
        Check(real.EngineVersion == VolatilityRunner.RequiredVersion && real.Modules.Count == 4 && real.Modules[0].ExitCode != 0,
            "Motor Volatility instalado rechaza ceros sintéticos como volcado compatible");
        Check(real.Status == "ERROR" && real.Integrity == "COINCIDE", "Error real del motor no se convierte en análisis correcto ni altera la evidencia");
    }
    if (args.Contains("--forensics"))
    {
        var fixtures = Path.GetFullPath(".tools/forensic-synthetic");
        foreach (var (tool, file, expected) in new[] {
            ("zip", "synthetic.zip", "SYNTHETIC.txt"), ("strings", "carving.bin", "SYNTHETIC"),
            ("browser", "History", "forensic synthetic"), ("disk", "carving.bin", "Imagen sin tabla"),
            ("foremost", "carving.bin", "Archivo recuperado"), ("floss", "sample.exe", "KRONOS_SYNTHETIC_FLOSS_MARKER"),
            ("aleapp", "android.zip", "forensic+synthetic"), ("ileapp", "ios.zip", "SYNTHETIC SAFARI") })
        {
            var item = await c.ImportAsync(Path.Combine(fixtures, file));
            Console.WriteLine("Ejecutando motor real " + tool + " sobre fixture sintético…");
            var forensic = await c.AnalyzeForensicAsync(item.Id, tool);
            Check(forensic.Status is "CORRECTO" or "REVISAR COBERTURA", $"Motor real {tool}: {forensic.Status}; {forensic.Error}");
            Check(forensic.Integrity == "COINCIDE", $"{tool} conserva la evidencia sin modificarla");
            var forensicTable = await c.LoadForensicTableAsync(forensic);
            Check(forensicTable.Rows.Any(row => row.Cells.Values.Any(value => value.Contains(expected))), $"{tool} muestra el contenido sintético esperado con fuentes");
            if (tool == "foremost")
            {
                var recovered = forensicTable.Rows.First(row => row.Cells.GetValueOrDefault("Tipo") == "Archivo recuperado por firma");
                var derived = await c.ImportRecoveredAsync(forensic, recovered.Cells["Fuente"]);
                Check(derived.ParentEvidenceId == item.Id && derived.DerivedFrom!.Contains(forensic.Id), "Archivo recuperado conserva vínculo a la evidencia padre y análisis");
                try { await c.ImportRecoveredAsync(forensic, "recovered/../../case.kronos.json"); throw new Exception("Aceptó ruta fuera de manifiesto"); }
                catch (InvalidDataException) { Check(true, "Rechaza importar rutas no incluidas en el manifiesto"); }
            }
            await File.AppendAllTextAsync(c.ResolveAnalysisPath(forensic.RelativeDirectory + "/results.json"), " ");
            try { await c.LoadForensicTableAsync(forensic); throw new Exception("Aceptó tabla alterada"); }
            catch (InvalidDataException) { Check(true, $"{tool} detecta manipulación de resultados"); }
        }
    }
    var exported = await c.ExportReportAsync();
    Check((await File.ReadAllTextAsync(exported)).Contains("Volatility 3") && (await File.ReadAllTextAsync(exported)).Contains("FALLO DE INTEGRIDAD"), "Informe incluye resultados RAM y fallos de integridad");
    c.Dispose();
    using var reopened = await CaseService.OpenAsync(Path.Combine(c.Root, CaseService.FileName));
    Check(reopened.Document.MemoryAnalyses.Count >= 5, "Reabre el caso con todo el historial RAM");
    Console.WriteLine($"{checks} comprobaciones de integración RAM superadas; datos exclusivamente sintéticos.");
}
finally { Directory.Delete(root, true); }

sealed class SyntheticRunner(string entry, string mode = "success") : IMemoryRunner
{
    public const string Rows = "[{\"PID\":4,\"ImageFileName\":\"SYNTHETIC\",\"__children\":[{\"PID\":500,\"ImageFileName\":\"SYNTHETIC_CHILD\",\"__children\":[]}]}]";
    public string EntryPath => entry;
    public int Calls { get; private set; }
    public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task<string> GetVersionAsync(string directory, CancellationToken cancellation) => Task.FromResult(VolatilityRunner.RequiredVersion);
    public async Task<int> ExecuteAsync(MemoryCommand command, CancellationToken cancellation)
    {
        Calls++;
        await File.WriteAllTextAsync(command.LogFile, "SYNTHETIC TEST OUTPUT");
        if (mode == "cancel") { Entered.TrySetResult(); await Task.Delay(Timeout.Infinite, cancellation); }
        var fail = (mode == "network-error" && command.Plugin.Contains("netscan")) || (mode == "info-error" && command.Plugin.Contains("info"));
        await File.WriteAllTextAsync(command.OutputFile, command.Plugin.Contains("netscan") || fail ? "[]" : Rows);
        return fail ? 1 : 0;
    }
}
