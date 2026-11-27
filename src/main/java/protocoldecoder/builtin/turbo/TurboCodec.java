package protocoldecoder.builtin.turbo;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.EditJson;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Turbo Stream responses ({@code text/vnd.turbo-stream.html}, or bodies / WebSocket frames that are
 * {@code <turbo-stream>} elements) as raw HTML. The edited HTML is sent as is (Content-Encoding re-applied), after
 * checking that it still consists of well-formed {@code <turbo-stream>} elements with an action.
 */
public final class TurboCodec implements MessageCodec {

    @Override
    public String decoderId() {
        return TurboDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        try {
            if (m.isRequest()) return List.of();
            byte[] raw = m.body();
            if (raw.length == 0) return List.of();
            String ce = m.isResponse() ? m.header("Content-Encoding") : null;
            if (!EditJson.reEncodable(raw, ce)) return List.of();
            byte[] body = EditJson.hasEncoding(ce) ? Codecs.decodeContent(raw, ce) : raw;
            if (body.length > EditJson.MAX_DOCUMENT_CHARS) return List.of();
            String text = new String(body, StandardCharsets.UTF_8);
            boolean streamType = m.isResponse() && m.contentType().toLowerCase(Locale.ROOT).contains(TurboStream.CONTENT_TYPE);
            boolean startsWithStream = text.stripLeading().regionMatches(true, 0, "<turbo-stream", 0, 13);
            if (!streamType && !startsWithStream) return List.of();
            if (TurboStream.parse(text).isEmpty()) return List.of();
            boolean utf8 = Arrays.equals(text.getBytes(StandardCharsets.UTF_8), body);
            return List.of(new EditJson.Doc("Turbo Stream (HTML)", "html", text, edited -> {
                if (edited.equals(text)) return MessagePatch.body(raw);
                validate(edited);
                if (!utf8) throw new EncodeException("The original body is not valid UTF-8; edits cannot be written back losslessly");
                return MessagePatch.body(EditJson.reEncode(edited.getBytes(StandardCharsets.UTF_8), body, raw, ce));
            }));
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    static void validate(String html) throws EncodeException {
        TurboStream.Result r = TurboStream.parse(html);
        if (r.isEmpty()) throw new EncodeException("No <turbo-stream> element found; Turbo ignores a stream response without one");
        for (String w : r.warnings()) {
            if (w.contains("is not closed") || w.contains("without an action")) throw new EncodeException("Invalid Turbo Stream: " + w);
        }
    }
}
