package protocoldecoder.core;

import protocoldecoder.util.TreeText;

import java.util.List;

/**
 * Output of a decoder.
 *
 * @param summary  one line shown above the tree (e.g. "DevExpress callback → ASPxGridView1 (PAGERONCLICK)")
 * @param root     decoded tree
 * @param text     optional plain-text rendering; when null the text view renders {@code root}
 * @param warnings non-fatal problems the user should know about (partial decode, unknown fields, ...)
 */
public record DecodeResult(String summary, DecodedNode root, String text, List<String> warnings) {

    public DecodeResult {
        summary = summary == null ? "" : summary;
        root = root == null ? DecodedNode.object("root") : root;
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }

    public static DecodeResult of(String summary, DecodedNode root) {
        return new DecodeResult(summary, root, null, List.of());
    }

    /** The text view content: explicit text if the decoder supplied one, else a rendering of the tree. */
    public String renderedText() {
        return text != null ? text : TreeText.render(root);
    }
}
