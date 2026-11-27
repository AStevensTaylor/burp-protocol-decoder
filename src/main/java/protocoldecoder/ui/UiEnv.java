package protocoldecoder.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.util.function.Consumer;
import javax.swing.UIManager;

/** Look-and-feel facts from Burp, so UI code doesn't depend on the Montoya API directly. */
public record UiEnv(boolean dark, Font editorFont, Consumer<Component> themer) {

    public static UiEnv standalone() {
        return new UiEnv(false, new Font(Font.MONOSPACED, Font.PLAIN, 12), c -> { });
    }

    public Color stringColor() { return dark ? new Color(0x98c379) : new Color(0x22863a); }
    public Color numberColor() { return dark ? new Color(0xd19a66) : new Color(0x005cc5); }
    public Color keywordColor() { return dark ? new Color(0xc678dd) : new Color(0xd73a49); }
    public Color noteColor() { return dark ? new Color(0x7f848e) : new Color(0x6a737d); }
    public Color htmlColor() { return dark ? new Color(0x61afef) : new Color(0x6f42c1); }
    public Color warningBackground() { return dark ? new Color(0x4d3b00) : new Color(0xfff5c2); }
    public Color errorColor() { return dark ? new Color(0xe06c75) : new Color(0xb31d28); }

    public Color foreground() {
        Color c = UIManager.getColor("Label.foreground");
        return c == null ? (dark ? Color.LIGHT_GRAY : Color.DARK_GRAY) : c;
    }

    public void theme(Component c) {
        try {
            themer.accept(c);
        } catch (RuntimeException ignored) {
            // theming is cosmetic
        }
    }
}
