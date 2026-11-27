package protocoldecoder.persistence;

/** Minimal string storage, implemented over Burp's preferences / project data (and an in-memory map in tests). */
public interface KeyValueStore {
    String get(String key);

    void set(String key, String value);

    static KeyValueStore inMemory() {
        java.util.Map<String, String> map = new java.util.concurrent.ConcurrentHashMap<>();
        return new KeyValueStore() {
            @Override
            public String get(String key) {
                return map.get(key);
            }

            @Override
            public void set(String key, String value) {
                if (value == null) map.remove(key);
                else map.put(key, value);
            }
        };
    }
}
