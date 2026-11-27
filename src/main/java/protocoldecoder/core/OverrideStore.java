package protocoldecoder.core;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manual "decode this message as …" choices made from the editor or the context menu, keyed by
 * {@link MessageContext#overrideKey()}.
 */
public final class OverrideStore {

    /** Decoder id meaning "do not decode this message". */
    public static final String NONE = "__none__";

    /** What the user chose, plus a label so the overrides list is readable. */
    public record Entry(String decoderId, String description) {
    }

    private static final int MAX_ENTRIES = 10_000;

    private final Map<String, Entry> entries = new LinkedHashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public synchronized Entry get(String key) {
        return entries.get(key);
    }

    public void set(MessageContext m, String decoderId) {
        synchronized (this) {
            entries.remove(m.overrideKey());
            entries.put(m.overrideKey(), new Entry(decoderId, m.kind().label() + "  " + m.method() + " " + m.url()));
            while (entries.size() > MAX_ENTRIES) {
                entries.remove(entries.keySet().iterator().next());
            }
        }
        fire();
    }

    public void clear(MessageContext m) {
        remove(m.overrideKey());
    }

    public void remove(String key) {
        boolean changed;
        synchronized (this) {
            changed = entries.remove(key) != null;
        }
        if (changed) fire();
    }

    public void clearAll() {
        synchronized (this) {
            entries.clear();
        }
        fire();
    }

    public synchronized Map<String, Entry> snapshot() {
        return new LinkedHashMap<>(entries);
    }

    public void load(Map<String, Entry> data) {
        synchronized (this) {
            entries.clear();
            entries.putAll(data);
        }
        fire();
    }

    public void addListener(Runnable l) {
        listeners.add(l);
    }

    private void fire() {
        listeners.forEach(Runnable::run);
    }
}
