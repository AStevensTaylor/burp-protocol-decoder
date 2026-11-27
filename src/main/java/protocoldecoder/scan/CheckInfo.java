package protocoldecoder.scan;

/** A check as listed in the UI. */
public record CheckInfo(String id, String name, String description, String decoderId, Kind kind, ActiveCheck.Scope scope) {

    public enum Kind {
        PASSIVE("Passive"), ACTIVE("Active"), INSERTION_POINTS("Insertion points");

        private final String label;

        Kind(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }
}
