// Copyright (c) 2026 José Luis Cabañas (JLC / UlysesX12).
// Distribuido bajo Volatility Software License 1.0. Véase LICENSE.md.
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Headless;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Kronos.Desktop;
using Kronos.Core;

var fixture = Path.Combine(Path.GetTempPath(), "kronos-ui-synthetic-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(fixture);
var source = Path.Combine(fixture, "synthetic.mem");
await File.WriteAllTextAsync(source, "SYNTHETIC MEMORY UI FIXTURE");
var sourceEntry = Path.Combine(fixture, "synthetic-entry.txt");
await File.WriteAllTextAsync(sourceEntry, "SYNTHETIC RUNNER");
var sampleCase = await CaseService.CreateAsync(fixture, "UI_SYNTHETIC", "Prueba UI");
var evidence = await sampleCase.ImportAsync(source);
await sampleCase.AnalyzeMemoryAsync(evidence.Id, new UiSyntheticRunner(sourceEntry), true);
var artifactRun = await sampleCase.AnalyzeForensicAsync(evidence.Id, "strings");
if (artifactRun.Status != "CORRECTO") throw new Exception(artifactRun.Error);

AppBuilder.Configure<App>().UseHeadless(new AvaloniaHeadlessPlatformOptions()).SetupWithoutStarting();
var window = new MainWindow();
window.Show();
Dispatcher.UIThread.RunJobs();
var all = window.GetVisualDescendants().ToArray();
if (all.OfType<TabControl>().Single().ItemCount != 6) throw new Exception("Faltan pestañas.");
Console.WriteLine("OK ventana renderizada y seis pestañas disponibles");
var verify = all.OfType<Button>().Single(b => b.Content as string == "Verificar copias");
verify.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
Dispatcher.UIThread.RunJobs();
if (!window.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text?.Contains("Crea o abre un caso primero") == true))
    throw new Exception("No muestra error al verificar sin caso.");
if (!verify.IsEnabled) throw new Exception("No libera la interfaz tras un error.");
Console.WriteLine("OK interacción real: error sin caso y recuperación de la interfaz");
var tabs = all.OfType<TabControl>().Single();
for (var i = 0; i < 6; i++) { tabs.SelectedIndex = i; Dispatcher.UIThread.RunJobs(); }
Console.WriteLine("OK navegación por todas las pestañas");
window.Close();
var loaded = new MainWindow(sampleCase);
loaded.Show();
var loadedTabs = loaded.GetVisualDescendants().OfType<TabControl>().Single();
loadedTabs.SelectedIndex = 1;
for (var i = 0; i < 300; i++)
{
    Dispatcher.UIThread.RunJobs();
    if (loaded.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "SYNTHETIC_TEST_PROCESS")) break;
    Thread.Sleep(10);
}
if (!loaded.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "SYNTHETIC_TEST_PROCESS")) throw new Exception("No muestra filas del análisis guardado en la tabla RAM.");
if (loaded.GetVisualDescendants().OfType<DataGrid>().Single().Bounds.Height < 200) throw new Exception("La tabla RAM queda demasiado pequeña.");
Console.WriteLine("OK la tabla RAM muestra filas verificadas de un caso sintético guardado");
loadedTabs.SelectedIndex = 2;
for (var i = 0; i < 300; i++)
{
    Dispatcher.UIThread.RunJobs();
    if (loaded.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "SYNTHETIC MEMORY UI FIXTURE")) break;
    Thread.Sleep(10);
}
if (!loaded.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "SYNTHETIC MEMORY UI FIXTURE")) throw new Exception("El laboratorio no muestra filas del análisis forense guardado.");
if (loaded.GetVisualDescendants().OfType<DataGrid>().Single().Bounds.Height < 200) throw new Exception("La tabla del laboratorio queda demasiado pequeña.");
Console.WriteLine("OK laboratorio muestra tablas forenses verificadas con espacio de lectura");
loaded.Close();
Directory.Delete(fixture, true);

sealed class UiSyntheticRunner(string entry) : IMemoryRunner
{
    public string EntryPath => entry;
    public Task<string> GetVersionAsync(string directory, CancellationToken cancellation) => Task.FromResult(VolatilityRunner.RequiredVersion);
    public async Task<int> ExecuteAsync(MemoryCommand command, CancellationToken cancellation)
    {
        await File.WriteAllTextAsync(command.LogFile, "SYNTHETIC UI TEST");
        await File.WriteAllTextAsync(command.OutputFile, "[{\"PID\":4,\"ImageFileName\":\"SYNTHETIC_TEST_PROCESS\",\"__children\":[]}]");
        return 0;
    }
}
