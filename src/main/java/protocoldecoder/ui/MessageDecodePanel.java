package protocoldecoder.ui;

import protocoldecoder.App;
import protocoldecoder.core.DecoderEngine;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.OverrideStore;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.core.Resolution;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessagePatch;

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
    private final EditPanel editPanel;
    private final javax.swing.JTabbedPane tabs;
    private volatile MessageContext message;
    /** Message as received from Burp; {@link #message} is it with {@link #patch} applied. */
    private volatile MessageContext original;
    private volatile MessagePatch patch = MessagePatch.NONE;
    private volatile ProtocolDecoder originalDecoder;
    private Runnable editListener = () -> { };
    private long decodedGeneration = -1;
    private boolean populating;

    public MessageDecodePanel(App app, UiEnv env) {
        this(app, env, false);
    }

    /** @param editable whether to offer the Edit tab (only for editable Burp editors) */
    public MessageDecodePanel(App app, UiEnv env, boolean editable) {
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
        if (editable) {
            editPanel = new EditPanel(env);
            editPanel.onFieldEdit(this::editField);
            editPanel.onDocumentApply(this::applyDocument);
            editPanel.onRevert(this::revertEdits);
            tabs = new javax.swing.JTabbedPane();
            tabs.addTab("Decoded", view);
            tabs.addTab("Edit", editPanel);
            add(tabs, BorderLayout.CENTER);
        } else {
            editPanel = null;
            tabs = null;
            add(view, BorderLayout.CENTER);
        }

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
        this.original = m;
        this.message = m;
        this.patch = MessagePatch.NONE;
        this.originalDecoder = null;
        refresh();
    }

    /** Called (on the EDT) whenever the edits change. */
    public void setEditListener(Runnable l) {
        this.editListener = l == null ? () -> { } : l;
    }

    /** Edits made in the Edit tab, relative to the message passed to {@link #setMessage}. */
    public MessagePatch edits() {
        return patch;
    }

    public boolean hasEdits() {
        return !patch.isEmpty();
    }

    void showEditTabForTest() {
        if (tabs != null) tabs.setSelectedIndex(1);
    }

    EditPanel editPanel() {
        return editPanel;
    }

    private void editField(EditEngine.Field f, String value) {
        MessageContext cur = message;
        runEdit(() -> app.editEngine().setField(cur, f, value), "Set " + f.label());
    }

    private void applyDocument(EditEngine.Document d, String text) {
        runEdit(() -> EditEngine.encode(d, text), "Applied " + d.document().title());
    }

    private void revertEdits() {
        patch = MessagePatch.NONE;
        message = original;
        editListener.run();
        editPanel.status("Edits reverted", false);
        refresh();
    }

    @FunctionalInterface
    private interface EditOp {
        MessagePatch run() throws EncodeException;
    }

    private void runEdit(EditOp op, String okText) {
        editPanel.status("Re-encoding…", false);
        WORKERS.submit(() -> {
            try {
                MessagePatch p = op.run();
                DecodedView.onEdt(() -> {
                    patch = patch.then(p);
                    message = patch.applyTo(original);
                    editListener.run();
                    editPanel.status(okText + " — message re-encoded", false);
                    refresh();
                });
            } catch (EncodeException | RuntimeException e) {
                DecodedView.onEdt(() -> {
                    editPanel.status(e.getMessage(), true);
                    refresh();
                });
            }
        });
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
            if (m != original && originalDecoder != null && (!r.hasDecoder() || r.source() == Resolution.Source.AUTO
                    && !r.decoder().id().equals(originalDecoder.id()))) {
                // Edited content may no longer carry the markers (or override key) that picked the decoder; keep it.
                r = new Resolution(originalDecoder, Resolution.Source.OVERRIDE, protocoldecoder.core.MatchResult.NONE, "edited message");
            }
            final Resolution res = r;
            List<DecoderEngine.Candidate> candidates = engine.candidates(m);
            DecoderEngine.Outcome o = engine.decode(m, res);
            OverrideStore.Entry override = app.overrides().get(original.overrideKey());
            List<EditEngine.Field> editFields = editPanel == null ? List.of() : app.editEngine().fields(m);
            List<EditEngine.Document> editDocs = editPanel == null ? List.of() : app.editEngine().documents(m);
            DecodedView.onEdt(() -> {
                if (seq.get() != mySeq) return;
                decodedGeneration = gen;
                lastResolvedId = res.hasDecoder() ? res.decoder().id() : null;
                if (m == original) originalDecoder = res.decoder();
                populatePicker(res, candidates, override);
                if (editPanel != null) {
                    editPanel.load(editFields, editDocs);
                    if (!EditEngine.editable(m)) editPanel.status("Message truncated to the size limit — editing disabled", true);
                }
                String timing = o.millis() > 0 ? "  ·  " + o.millis() + " ms" : "";
                how.setText(res.describe() + timing + (m.truncated() ? "  ·  message truncated to size limit" : "")
                        + (hasEdits() ? "  ·  edited" : ""));
                if (o.ok()) view.show(o.result());
                else if (res.hasDecoder()) view.showError(o.error());
                else view.showMessage(res.source() == Resolution.Source.NONE
                            ? "No decoder recognised this message — pick one above, or add a rule or script"
                            : res.describe());
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
        MessageContext m = original;
        Choice c = (Choice) picker.getSelectedItem();
        if (m == null || c == null) return;
        if (c.decoderId() == null) app.overrides().clear(m);
        else app.overrides().set(m, c.decoderId());
        // The choice also governs how the edited message is decoded.
        originalDecoder = c.decoderId() == null || OverrideStore.NONE.equals(c.decoderId())
                ? null : app.registry().byId(c.decoderId()).orElse(null);
        refresh();
    }
}
