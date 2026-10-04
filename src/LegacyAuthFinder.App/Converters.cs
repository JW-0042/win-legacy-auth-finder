using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using LegacyAuthFinder.Core;

namespace LegacyAuthFinder.App;

internal static class Palette
{
    public static SolidColorBrush Make(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    public static readonly SolidColorBrush Des = Make(0xB0, 0x12, 0x4F);
    public static readonly SolidColorBrush Ntlm = Make(0xD9, 0x30, 0x25);
    public static readonly SolidColorBrush Rc4 = Make(0xC2, 0x5E, 0x00);
    public static readonly SolidColorBrush Ok = Make(0x1F, 0x9D, 0x55);
    public static readonly SolidColorBrush Busy = Make(0x2F, 0x80, 0xED);
    public static readonly SolidColorBrush Gray = Make(0x8A, 0x93, 0x9E);
}

/// <summary>Finding type to accent brush. Readable in both light and dark themes.</summary>
public sealed class KindBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        LegacyKind.Des => Palette.Des,
        LegacyKind.Ntlmv1 => Palette.Ntlm,
        LegacyKind.Rc4 => Palette.Rc4,
        _ => Palette.Gray,
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class FileStateBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        FileState.Done => Palette.Ok,
        FileState.Scanning or FileState.Queued => Palette.Busy,
        FileState.Error => Palette.Ntlm,
        _ => Palette.Gray,
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        (value is true) ^ Invert ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}
