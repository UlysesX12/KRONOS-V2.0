// Copyright (c) 2026 Jose Luis Cabanas (JLC / UlysesX12).
// Distribuido bajo Volatility Software License 1.0; vease LICENSE.md.
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Data.Converters;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Kronos.Core;

namespace Kronos.Desktop;

public sealed partial class MainWindow
{
    private static string DefaultPython()
    {
        try { return VolatilityRunner.Discover().PythonExecutable; }
        catch (FileNotFoundException) { return OperatingSystem.IsWindows() ? "python" : "python3"; }
    }
    private sealed record MemoryEvidenceChoice(Evidence Evidence)
    {
        public override string ToString() => $"{Path.GetFileName(Evidence.Source)} · {Evidence.Size:N0} bytes";
    }
    private readonly ComboBox memoryEvidence = new() { PlaceholderText = "Selecciona una evidencia importada", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly ComboBox memoryRuns = new() { PlaceholderText = "Análisis guardados del caso", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly ComboBox memoryModules = new() { PlaceholderText = "Módulo y estado", HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly TextBox memoryQuery = new() { Watermark = "Buscar PID, proceso, dirección IP o texto…" };
    private readonly TextBlock memoryHint = new() { Text = "Crea un caso, importa el volcado y ejecuta el análisis Windows.", TextWrapping = TextWrapping.Wrap };
    private readonly DataGrid memoryGrid = new() { IsReadOnly = true, AutoGenerateColumns = false, CanUserResizeColumns = true, GridLinesVisibility = DataGridGridLinesVisibility.Horizontal, MinHeight = 150 };
    private readonly CheckBox memoryOffline = new() { Content = "Sin conexión: usar solo símbolos disponibles", IsChecked = false };
    private readonly Button memoryCancel = new() { Content = "Cancelar", IsEnabled = false, Margin = new Thickness(0, 3, 10, 3) };
    private MemoryTable? memoryTable;
    private int memoryLoadGeneration;

    private Control CreateMemoryPanel()
    {
        var actions = new WrapPanel();
        actions.Children.Add(Action("Importar volcado RAM…", ImportMemory, true));
        actions.Children.Add(Action("Analizar RAM Windows", AnalyzeMemory, true));
        actions.Children.Add(memoryCancel);
        actions.Children.Add(Action("Abrir carpeta del análisis", () =>
        {
            var c = RequireCase();
            if (memoryRuns.SelectedItem is not MemoryAnalysis a) throw new InvalidOperationException("Selecciona un análisis guardado.");
            OpenPath(c.ResolveAnalysisPath(a.RelativeDirectory)); return Task.CompletedTask;
        }));
        actions.Children.Add(Action("Añadir fila a notas", AddMemoryFinding));
        memoryCancel.Click += (_, _) => operationCancellation?.Cancel();
        memoryRuns.SelectionChanged += (_, _) =>
        {
            memoryLoadGeneration++;
            memoryModules.ItemsSource = (memoryRuns.SelectedItem as MemoryAnalysis)?.Modules;
            memoryModules.SelectedIndex = memoryModules.ItemCount > 0 ? 0 : -1;
            if (memoryRuns.SelectedItem is MemoryAnalysis run)
                memoryHint.Text = $"{run.Status} · integridad {run.Integrity} · Volatility {run.EngineVersion}\n{run.Error}";
            else { memoryTable = null; memoryGrid.ItemsSource = null; }
        };
        memoryModules.SelectionChanged += async (_, _) => await LoadMemoryResults();
        memoryQuery.TextChanged += (_, _) => FilterMemory();
        var controls = new StackPanel { Spacing = 8, Children = {
            new TextBlock { Text = "Análisis de memoria Windows · Volatility 3", FontSize = 20 },
            new TextBlock { Text = "Información del sistema, procesos, líneas de comando y conexiones. Trabaja sobre la copia del caso y comprueba SHA-256 antes y después. La compatibilidad depende del volcado y sus símbolos; una extensión no identifica el formato.", TextWrapping = TextWrapping.Wrap },
            memoryEvidence, actions, memoryOffline,
            new TextBlock { Text = "Con conexión, el motor puede descargar símbolos de Microsoft usando identificadores técnicos; no envía el volcado. Usa una copia de laboratorio y revisa la cobertura de cada módulo.", FontSize = 12, Foreground = Brushes.LightGray, TextWrapping = TextWrapping.Wrap },
            memoryRuns, memoryModules, memoryQuery, memoryHint
        }};
        var grid = new Grid { RowDefinitions = new RowDefinitions("Auto,*"), RowSpacing = 10 };
        grid.Children.Add(controls); Grid.SetRow(memoryGrid, 1); grid.Children.Add(memoryGrid);
        return grid;
    }
    private void RefreshMemory()
    {
        if (current is null) return;
        var id = (memoryEvidence.SelectedItem as MemoryEvidenceChoice)?.Evidence.Id;
        var choices = current.Document.Evidence.Select(e => new MemoryEvidenceChoice(e)).ToList();
        memoryEvidence.ItemsSource = choices;
        memoryEvidence.SelectedItem = choices.FirstOrDefault(e => e.Evidence.Id == id) ?? choices.LastOrDefault();
        var selected = (memoryRuns.SelectedItem as MemoryAnalysis)?.Id;
        memoryRuns.ItemsSource = current.Document.MemoryAnalyses.ToList();
        memoryRuns.SelectedItem = current.Document.MemoryAnalyses.FirstOrDefault(a => a.Id == selected) ?? current.Document.MemoryAnalyses.LastOrDefault();
    }
    private async Task ImportMemory()
    {
        var c = RequireCase();
        var files = await StorageProvider.OpenFilePickerAsync(new() { Title = "Volcado de memoria para importar", AllowMultiple = false,
            FileTypeFilter = [new FilePickerFileType("Volcados RAM") { Patterns = ["*.mem", "*.raw", "*.dmp", "*.vmem", "*.bin"] }, FilePickerFileTypes.All] });
        var path = files.FirstOrDefault()?.TryGetLocalPath(); if (path is null) return;
        await c.ImportAsync(path, new Progress<string>(text => status.Text = text), operationCancellation!.Token);
        completionMessage = "Volcado importado y verificado. Pulsa Analizar RAM Windows para interpretar su contenido.";
    }
    private async Task AnalyzeMemory()
    {
        var c = RequireCase();
        if (memoryEvidence.SelectedItem is not MemoryEvidenceChoice choice) throw new InvalidOperationException("Importa o selecciona primero un volcado de memoria.");
        var analysis = await c.AnalyzeMemoryAsync(choice.Evidence.Id, VolatilityRunner.Discover(), memoryOffline.IsChecked == true,
            new Progress<string>(message => { status.Text = message; memoryHint.Text = message; }), operationCancellation!.Token);
        results.Text = $"RAM: {analysis.Status}; integridad {analysis.Integrity}\n{analysis.Error}\n" +
            string.Join("\n\n", analysis.Modules.Select(m => $"{m.Name}: {m.Status}; {m.Rows} filas. {m.Error}"));
        memoryRuns.ItemsSource = c.Document.MemoryAnalyses.ToList(); memoryRuns.SelectedItem = analysis;
        completionMessage = $"Análisis RAM: {analysis.Status}. Revisa el estado de cada módulo en Análisis RAM.";
    }
    private async Task LoadMemoryResults()
    {
        var generation = ++memoryLoadGeneration;
        memoryTable = null; memoryGrid.ItemsSource = null; memoryGrid.Columns.Clear();
        if (current is null || memoryRuns.SelectedItem is not MemoryAnalysis run || memoryModules.SelectedItem is not MemoryModule module) return;
        memoryHint.Text = $"{run.Status} · integridad {run.Integrity} · {module.Name}: {module.Status}\n{run.Error}\n{module.Error}";
        if (module.Status != "CORRECTO") return;
        try
        {
            var table = await current.LoadMemoryTableAsync(run, module);
            if (generation != memoryLoadGeneration) return;
            memoryTable = table;
            foreach (var column in table.Columns)
            {
                var key = column;
                memoryGrid.Columns.Add(new DataGridTextColumn { Header = key,
                    Binding = new Binding { Converter = new FuncValueConverter<MemoryRow, string>(row => row?.Cells.GetValueOrDefault(key) ?? "") } });
            }
            FilterMemory();
            memoryHint.Text = $"{module.Name}: {module.Status} · {table.TotalRows:N0} filas · {Math.Min(table.TotalRows, 10000):N0} cargadas · integridad de salida verificada. {run.Error}";
        }
        catch (Exception ex) { if (generation == memoryLoadGeneration) memoryHint.Text = "No se pueden cargar los resultados: " + ex.Message; }
    }
    private void FilterMemory()
    {
        var query = memoryQuery.Text ?? "";
        memoryGrid.ItemsSource = memoryTable?.Rows.Where(row => row.Cells.Values.Any(value => value.Contains(query, StringComparison.OrdinalIgnoreCase))).ToList();
    }
    private Task AddMemoryFinding()
    {
        RequireCase();
        if (memoryRuns.SelectedItem is not MemoryAnalysis run || memoryModules.SelectedItem is not MemoryModule module || memoryGrid.SelectedItem is not MemoryRow row)
            throw new InvalidOperationException("Selecciona una fila de resultados para añadirla a las notas.");
        notes.Text += $"\n\nHallazgo RAM · evidencia {run.EvidenceId} · Volatility {run.EngineVersion}\nFuente: {module.ResultsPath} · JSON Pointer {row.JsonPointer}\n" +
            string.Join("; ", row.Cells.Select(cell => $"{cell.Key}: {cell.Value}")) + "\nInterpretación del profesional: ";
        completionMessage = "Fila añadida a las notas con su fuente. Completa la interpretación y guarda las notas.";
        return Task.CompletedTask;
    }
}
