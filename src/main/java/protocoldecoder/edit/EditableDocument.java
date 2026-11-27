package protocoldecoder.edit;

/**
 * A decoded view of (part of) a message that the user can edit as text and that the protocol can encode back, e.g. a
 * SAML assertion as XML, a GraphQL document, or a protobuf message in text form. Bound to the message it was opened
 * from.
 */
public interface EditableDocument {

    /** Short label for the document picker, e.g. "SAMLResponse (XML)". */
    String title();

    /** Syntax hint for the editor: "json", "xml", "graphql", "html", "protobuf-text" or "text". */
    default String syntax() {
        return "text";
    }

    /** The editable text as initially shown. */
    String text();

    /** Encodes edited text back into the message. Must re-apply every encoding layer (lengths, compression, base64…). */
    MessagePatch encode(String editedText) throws EncodeException;
}
