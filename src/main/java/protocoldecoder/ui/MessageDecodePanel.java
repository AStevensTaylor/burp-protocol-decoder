package protocoldecoder.ui;

import protocoldecoder.App;
import protocoldecoder.core.DecoderEngine;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.OverrideStore;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.core.Resolution;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;

/**
 * The "Decoded" tab content for a message: a "Decoder" picker (automatic, a specific decoder, or none — the choice is
 * remembered for this message), an explanation of why a decoder was chosen, and the decoded view.
 */
public final class MessageDecodePanel extends JPanel {

    /** Picker entry. decoderId null = automatic (rules + detection). */
    record Choice(String label, String decoderId) {
        @Override
        public String toString() {
            return label;
        }
    }

    private static final AtomicInteger THREADS = new AtomicInteger();
    static final ExecutorService WORKERS = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "protocol-decoder-ui-" + THREADS.incrementAndGet());
        t.setDaemon(true);
        t.setContextClassLoader(MessageDecodePanel.class.getClassLoader());
        return t;
    });

    private final App app;
    private final UiEnv env;
    private final DecodedView view;
    private final JComboBox<Choice> picker = new JComboBox<>();
    private final JLabel how = new JLabel(" ");
    private final JButton createRule = new JButton("Create rule…");
    private final JButton copy = new JButton("Copy");
    private final AtomicLong seq = new AtomicLong();
    private volatile MessageContext message;
    private long decodedGeneration = -1;
    private boolean populating;

    public MessageDecodePanel(App app, UiEnv env) {
        super(new BorderLayout());
        this.app = app;
        this.env = env;
        this.view = new DecodedView(env);

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 3));
        bar.add(new JLabel("Decoder:"));
        picker.setToolTipText("Choose how this message is decoded. The choice is remembered for this message.");
        bar.add(picker);
        bar.add(createRule);
        bar.add(copy);
        how.setForeground(env.noteColor());
        how.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));
        bar.add(how);

        picker.addActionListener(e -> onPick());
        createRule.setToolTipText("Create a rule that always decodes messages like this one with the selected decoder");
        createRule.addActionListener(e -> {
            MessageContext m = message;
            if (m == null) return;
            Choice c = (Choice) picker.getSelectedItem();
            String id = c == null || c.decoderId() == null ? currentDecoderId() : c.decoderId();
            RuleEditorDialog.createFromMessage(this, app, env, m, id);
        });
        copy.addActionListener(e -> DecodedView.copy(view.fullText()));

        add(bar, BorderLayout.NORTH);
        add(view, BorderLayout.CENTER);

        // Re-decode when the tab is shown again after rules/decoders/overrides changed elsewhere.
        addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorAdded(AncestorEvent event) {
                if (message != null && decodedGeneration != app.engine().generation()) refresh();
            }

            @Override
            public void ancestorRemoved(AncestorEvent event) {
            }

            @Override
            public void ancestorMoved(AncestorEvent event) {
            }
        });
    }

    private String lastResolvedId;

    private String currentDecoderId() {
        return lastResolvedId;
    }

    public void setMessage(MessageContext m) {
        this.message = m;
        refresh();
    }

    DecodedView view() {
        return view;
    }

    String statusText() {
        return how.getText();
    }

    int pickerCount() {
        return picker.getItemCount();
    }

    void pick(int index) {
        picker.setSelectedIndex(index);
    }

    public MessageContext message() {
        return message;
    }

    /** Selected value in the view, for Burp's "selected data". */
    public String selectedValue() {
        return view.selectedValue();
    }

    private void refresh() {
        MessageContext m = message;
        if (m == null) {
            view.showMessage("No message");
            return;
        }
        long mySeq = seq.incrementAndGet();
        view.showMessage("Decoding…");
        DecoderEngine engine = app.engine();
        WORKERS.submit(() -> {
            long gen = engine.generation();
            Resolution r = engine.resolve(m);
            List<DecoderEngine.Candidate> candidates = engine.candidates(m);
            DecoderEngine.Outcome o = engine.decode(m, r);
            OverrideStore.Entry override = app.overrides().get(m.overrideKey());
            DecodedView.onEdt(() -> {
                if (seq.get() != mySeq) return;
                decodedGeneration = gen;
                lastResolvedId = r.hasDecoder() ? r.decoder().id() : null;
                populatePicker(r, candidates, override);
                String timing = o.millis() > 0 ? "  ·  " + o.millis() + " ms" : "";
                how.setText(r.describe() + timing + (m.truncated() ? "  ·  message truncated to size limit" : ""));
                if (o.ok()) view.show(o.result());
                else if (r.hasDecoder()) view.showError(o.error());
                else view.showMessage(r.source() == Resolution.Source.NONE
                            ? "No decoder recognised this message — pick one above, or add a rule or script"
                            : r.describe());
            });
        });
    }

    private void populatePicker(Resolution r, List<DecoderEngine.Candidate> candidates, OverrideStore.Entry override) {
        populating = true;
        try {
            DefaultComboBoxModel<Choice> model = new DefaultComboBoxModel<>();
            String autoLabel = "Automatic";
            if (override == null) {
                autoLabel += r.hasDecoder() ? " (" + r.decoder().name() + ")" : " (none)";
            }
            Choice auto = new Choice(autoLabel, null);
            model.addElement(auto);
            Choice selected = auto;
            for (DecoderEngine.Candidate c : candidates) {
                ProtocolDecoder d = c.decoder();
                MatchResult mr = c.match();
                String label = d.name() + (mr.matched() ? "  —  " + mr.confidence() + "%" : "")
                        + (app.registry().isEnabled(d.id()) ? "" : "  (disabled)");
                Choice ch = new Choice(label, d.id());
                model.addElement(ch);
                if (override != null && d.id().equals(override.decoderId())) selected = ch;
            }
            Choice none = new Choice("Don't decode", OverrideStore.NONE);
            model.addElement(none);
            if (override != null && OverrideStore.NONE.equals(override.decoderId())) selected = none;
            picker.setModel(model);
            picker.setSelectedItem(selected);
        } finally {
            populating = false;
        }
    }

    private void onPick() {
        if (populating) return;
        MessageContext m = message;
        Choice c = (Choice) picker.getSelectedItem();
        if (m == null || c == null) return;
        if (c.decoderId() == null) app.overrides().clear(m);
        else app.overrides().set(m, c.decoderId());
        refresh();
    }
}
