package protocoldecoder.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * All known decoders (built-in first, then user scripts) plus their enabled state. Thread-safe: reads take a
 * snapshot, writes replace it and notify listeners.
 */
public final class DecoderRegistry {

    private volatile List<ProtocolDecoder> decoders = List.of();
    private final Set<String> disabled = ConcurrentHashMap.newKeySet();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public synchronized void register(ProtocolDecoder d) {
        List<ProtocolDecoder> copy = new ArrayList<>(decoders);
        copy.removeIf(x -> x.id().equals(d.id()));
        copy.add(d);
        decoders = List.copyOf(copy);
        fire();
    }

    /** Replaces the decoder with the same id in place (keeping its position), or appends it. */
    public synchronized void replace(ProtocolDecoder d) {
        List<ProtocolDecoder> copy = new ArrayList<>(decoders);
        boolean done = false;
        for (int i = 0; i < copy.size(); i++) {
            if (copy.get(i).id().equals(d.id())) {
                copy.set(i, d);
                done = true;
                break;
            }
        }
        if (!done) copy.add(d);
        decoders = List.copyOf(copy);
        fire();
    }

    public synchronized void unregister(String id) {
        List<ProtocolDecoder> copy = new ArrayList<>(decoders);
        if (copy.removeIf(x -> x.id().equals(id))) {
            decoders = List.copyOf(copy);
            fire();
        }
    }

    public List<ProtocolDecoder> all() {
        return decoders;
    }

    public List<ProtocolDecoder> enabled() {
        List<ProtocolDecoder> out = new ArrayList<>();
        for (ProtocolDecoder d : decoders) if (!disabled.contains(d.id())) out.add(d);
        return out;
    }

    public Optional<ProtocolDecoder> byId(String id) {
        if (id == null) return Optional.empty();
        for (ProtocolDecoder d : decoders) if (d.id().equals(id)) return Optional.of(d);
        return Optional.empty();
    }

    public boolean isEnabled(String id) {
        return !disabled.contains(id);
    }

    public void setEnabled(String id, boolean enabled) {
        boolean changed = enabled ? disabled.remove(id) : disabled.add(id);
        if (changed) fire();
    }

    public Set<String> disabledIds() {
        return Set.copyOf(disabled);
    }

    public void setDisabledIds(Set<String> ids) {
        disabled.clear();
        disabled.addAll(ids);
        fire();
    }

    public void addListener(Runnable l) {
        listeners.add(l);
    }

    private void fire() {
        listeners.forEach(Runnable::run);
    }
}
