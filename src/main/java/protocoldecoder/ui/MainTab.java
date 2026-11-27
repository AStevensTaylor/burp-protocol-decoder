package protocoldecoder.ui;

import protocoldecoder.App;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

/** The "Protocol Decoder" suite tab. */
public final class MainTab extends JPanel {

    public MainTab(App app, UiEnv env) {
        super(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Decoders", new DecodersPanel(app, env));
        tabs.addTab("Rules", new RulesPanel(app, env));
        tabs.addTab("Manual choices", new OverridesPanel(app));
        tabs.addTab("Scan checks", new ScanChecksPanel(app));
        tabs.addTab("Settings & help", new SettingsPanel(app, env));
        add(tabs, BorderLayout.CENTER);
    }
}
