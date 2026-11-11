// Copyright (c) 2026 José Luis Cabañas (JLC / UlysesX12).
// Distribuido bajo Volatility Software License 1.0. Véase LICENSE.md.
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Themes.Fluent;
using Avalonia.Markup.Xaml.Styling;

namespace Kronos.Desktop;
internal static class Program
{
    [STAThread]
    public static void Main(string[] args) => BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UsePlatformDetect().LogToTrace();
}
public sealed class App : Application
{
    public override void Initialize()
    {
        Styles.Add(new FluentTheme());
        Styles.Add(new StyleInclude(new Uri("avares://Kronos.Desktop")) { Source = new Uri("avares://Avalonia.Controls.DataGrid/Themes/Fluent.xaml") });
        RequestedThemeVariant = Avalonia.Styling.ThemeVariant.Dark;
    }
    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop) desktop.MainWindow = new MainWindow();
        base.OnFrameworkInitializationCompleted();
    }
}
