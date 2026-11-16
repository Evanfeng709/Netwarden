import 'package:flutter/material.dart';

/// 一套配色。与桌面端保持一致：
/// 曜石（深色）+ 亚麻（暖浅色）。
class KwPalette {
  const KwPalette({
    required this.id,
    required this.name,
    required this.brightness,
    required this.bg,
    required this.bgElev,
    required this.panel,
    required this.surface2,
    required this.surface3,
    required this.border,
    required this.text,
    required this.dim,
    required this.faint,
    required this.accent,
    required this.accentSoft,
    required this.ok,
    required this.okSoft,
    required this.warn,
    required this.warnSoft,
    required this.danger,
    required this.dangerSoft,
  });

  final String id;
  final String name;
  final Brightness brightness;
  final Color bg;
  final Color bgElev;
  final Color panel;
  final Color surface2;
  final Color surface3;
  final Color border;
  final Color text;
  final Color dim;
  final Color faint;
  final Color accent;
  final Color accentSoft;
  final Color ok;
  final Color okSoft;
  final Color warn;
  final Color warnSoft;
  final Color danger;
  final Color dangerSoft;

  bool get isDark => brightness == Brightness.dark;
}

const List<KwPalette> kwPalettes = [
  KwPalette(
    id: 'obsidian',
    name: '曜石',
    brightness: Brightness.dark,
    bg: Color(0xFF0B0D12),
    bgElev: Color(0xFF10141D),
    panel: Color(0xFF141923),
    surface2: Color(0xFF0E121A),
    surface3: Color(0xFF1B2230),
    border: Color(0xFF212938),
    text: Color(0xFFE6EDF3),
    dim: Color(0xFF9AA7B6),
    faint: Color(0xFF637081),
    accent: Color(0xFF3B82F6),
    accentSoft: Color(0xFF152540),
    ok: Color(0xFF10B981),
    okSoft: Color(0xFF0F2922),
    warn: Color(0xFFD6A034),
    warnSoft: Color(0xFF2A2418),
    danger: Color(0xFFF85149),
    dangerSoft: Color(0xFF2A1618),
  ),
  KwPalette(
    id: 'linen',
    name: '亚麻',
    brightness: Brightness.light,
    bg: Color(0xFFF6F3EC),
    bgElev: Color(0xFFFDFBF6),
    panel: Color(0xFFFCF9F2),
    surface2: Color(0xFFEFEBE1),
    surface3: Color(0xFFE7E1D5),
    border: Color(0xFFDCD5C6),
    text: Color(0xFF26231E),
    dim: Color(0xFF625B4F),
    faint: Color(0xFF91897B),
    accent: Color(0xFF2B5FB8),
    accentSoft: Color(0xFFE3EAF6),
    ok: Color(0xFF1F7A45),
    okSoft: Color(0xFFE1F0E6),
    warn: Color(0xFFA8580C),
    warnSoft: Color(0xFFF6E9D3),
    danger: Color(0xFFC9342D),
    dangerSoft: Color(0xFFF8E3E1),
  ),
];

/// 全局取色器：界面里 100 多处 `KwColors.xxx` 都读当前调色板。
/// 切主题只需要 `KwColors.select(i)` + 顶层 setState。
class KwColors {
  static int _index = 0;

  static KwPalette get palette => kwPalettes[_index];

  static void select(int index) {
    _index = index % kwPalettes.length;
    if (_index < 0) _index += kwPalettes.length;
  }

  static Color get bg => palette.bg;
  static Color get bgElev => palette.bgElev;
  static Color get panel => palette.panel;
  static Color get surface2 => palette.surface2;
  static Color get surface3 => palette.surface3;
  static Color get border => palette.border;
  static Color get text => palette.text;
  static Color get dim => palette.dim;
  static Color get faint => palette.faint;
  static Color get accent => palette.accent;
  static Color get accentSoft => palette.accentSoft;
  static Color get ok => palette.ok;
  static Color get okSoft => palette.okSoft;
  static Color get warn => palette.warn;
  static Color get warnSoft => palette.warnSoft;
  static Color get danger => palette.danger;
  static Color get dangerSoft => palette.dangerSoft;
}

class KwTheme {
  static ThemeData build() {
    final p = KwColors.palette;
    final scheme = ColorScheme(
      brightness: p.brightness,
      primary: p.accent,
      onPrimary: Colors.white,
      secondary: p.accent,
      onSecondary: Colors.white,
      error: p.danger,
      onError: Colors.white,
      surface: p.panel,
      onSurface: p.text,
    );

    return ThemeData(
      useMaterial3: true,
      brightness: p.brightness,
      colorScheme: scheme,
      scaffoldBackgroundColor: p.bg,
      canvasColor: p.bgElev,
      dividerColor: p.border,
      visualDensity: VisualDensity.compact,
      appBarTheme: AppBarTheme(
        backgroundColor: p.bgElev,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        centerTitle: false,
        toolbarHeight: 50,
        titleTextStyle: TextStyle(
          color: p.text,
          fontSize: 15,
          fontWeight: FontWeight.w600,
        ),
        iconTheme: IconThemeData(color: p.dim, size: 20),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: p.bgElev,
        indicatorColor: p.accentSoft,
        labelTextStyle: WidgetStateProperty.all(
          TextStyle(fontSize: 10.5, color: p.dim),
        ),
        iconTheme: WidgetStateProperty.resolveWith((states) {
          final selected = states.contains(WidgetState.selected);
          return IconThemeData(size: 20, color: selected ? p.accent : p.faint);
        }),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: p.surface2,
        hintStyle: TextStyle(color: p.faint, fontSize: 12.5),
        labelStyle: TextStyle(color: p.dim, fontSize: 12.5),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 11,
          vertical: 11,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: p.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: p.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: p.accent),
        ),
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: p.bgElev,
        surfaceTintColor: Colors.transparent,
        titleTextStyle: TextStyle(
          color: p.text,
          fontSize: 15,
          fontWeight: FontWeight.w600,
        ),
        contentTextStyle: TextStyle(color: p.dim, fontSize: 13, height: 1.5),
      ),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: p.surface3,
        contentTextStyle: TextStyle(color: p.text, fontSize: 12.5),
        behavior: SnackBarBehavior.floating,
      ),
      bottomSheetTheme: BottomSheetThemeData(
        backgroundColor: p.bgElev,
        surfaceTintColor: Colors.transparent,
        modalBackgroundColor: p.bgElev,
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(foregroundColor: p.accent),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: p.accent,
          foregroundColor: Colors.white,
          minimumSize: const Size(0, 38),
          textStyle: const TextStyle(fontSize: 13),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: p.text,
          side: BorderSide(color: p.border),
          minimumSize: const Size(0, 38),
          textStyle: const TextStyle(fontSize: 13),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
      progressIndicatorTheme: ProgressIndicatorThemeData(color: p.accent),
      listTileTheme: ListTileThemeData(
        iconColor: p.dim,
        textColor: p.text,
        dense: true,
      ),
    );
  }
}

/// 主题选择面板：色块 + 名称，点一下立即生效。
Widget paletteSheet(
  BuildContext context, {
  required int current,
  required ValueChanged<int> onSelect,
}) {
  return SafeArea(
    // 手机上横屏或小窗时整块会超出弹层高度，滚动兜底。
    child: SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 10),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            '外观主题',
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w600,
              color: KwColors.text,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            '曜石（深色）与 亚麻（暖浅色），与桌面端主题一致。',
            style: TextStyle(fontSize: 11.5, color: KwColors.faint),
          ),
          const SizedBox(height: 12),
          ...List.generate(kwPalettes.length, (i) {
            final p = kwPalettes[i];
            final selected = i == current;
            return InkWell(
              onTap: () => onSelect(i),
              borderRadius: BorderRadius.circular(8),
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 7),
                child: Row(
                  children: [
                    Container(
                      width: 42,
                      height: 26,
                      decoration: BoxDecoration(
                        color: p.bg,
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(color: p.border),
                      ),
                      alignment: Alignment.center,
                      child: Container(
                        width: 14,
                        height: 14,
                        decoration: BoxDecoration(
                          color: p.accent,
                          shape: BoxShape.circle,
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        p.name,
                        style: TextStyle(
                          fontSize: 13,
                          color: KwColors.text,
                          fontWeight: selected
                              ? FontWeight.w600
                              : FontWeight.w400,
                        ),
                      ),
                    ),
                    Text(
                      p.isDark ? '深色' : '浅色',
                      style: TextStyle(
                        fontSize: 11,
                        fontFamily: 'monospace',
                        color: KwColors.faint,
                      ),
                    ),
                    const SizedBox(width: 10),
                    if (selected)
                      Icon(Icons.check_rounded, size: 17, color: p.accent),
                  ],
                ),
              ),
            );
          }),
        ],
      ),
    ),
  );
}