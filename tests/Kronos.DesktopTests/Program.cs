// Copyright (c) 2026 José Luis Cabañas (JLC / UlysesX12).
// Todos los derechos reservados sobre las aportaciones propias. Véase LICENSE.md.
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Headless;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Kronos.Desktop;

AppBuilder.Configure<App>().UseHeadless(new AvaloniaHeadlessPlatformOptions()).SetupWithoutStarting();
var window = new MainWindow();
window.Show();
Dispatcher.UIThread.RunJobs();
var all = window.GetVisualDescendants().ToArray();
if (all.OfType<TabControl>().Single().ItemCount != 4) throw new Exception("Faltan pestañas.");
Console.WriteLine("OK ventana renderizada y cuatro pestañas disponibles");
var verify = all.OfType<Button>().Single(b => b.Content as string == "Verificar copias");
verify.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
Dispatcher.UIThread.RunJobs();
if (!window.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text?.Contains("Crea o abre un caso primero") == true))
    throw new Exception("No muestra error al verificar sin caso.");
if (!verify.IsEnabled) throw new Exception("No libera la interfaz tras un error.");
Console.WriteLine("OK interacción real: error sin caso y recuperación de la interfaz");
var tabs = all.OfType<TabControl>().Single();
for (var i = 0; i < 4; i++) { tabs.SelectedIndex = i; Dispatcher.UIThread.RunJobs(); }
Console.WriteLine("OK navegación por todas las pestañas");
window.Close();
