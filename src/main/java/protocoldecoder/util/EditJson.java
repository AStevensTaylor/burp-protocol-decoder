package protocoldecoder.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessagePatch;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Helpers shared by document codecs: strict JSON parsing with user-facing line/column errors, pretty and compact
 * (JavaScript {@code JSON.stringify}-like) serialisation, and HTTP Content-Encoding re-application.
 */
public final class EditJson {

    /** Compact, no HTML escaping, nulls kept: what {@code JSON.stringify} produces for the same tree. */
    private static final Gson COMPACT = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    private static final Gson PRETTY = new GsonBuilder().disableHtmlEscaping().serializeNulls().setPrettyPrinting().create();
    private static final Pattern AT = Pattern.compile("at line (\\d+) column (\\d+)");

    /** Largest decoded text a codec offers as a document. */
    public static final int MAX_DOCUMENT_CHARS = 4 * 1024 * 1024;
    /** Most documents a codec offers for one message. */
    public static final int MAX_DOCUMENTS = 10;

    private EditJson() {
    }

    /** Encodes edited document text into a patch. */
    @FunctionalInterface
    public interface Encoder {
        MessagePatch encode(String text) throws EncodeException;
    }

    /** A simple document: fixed title, syntax and text plus an encoder. */
    public record Doc(String title, String syntax, String text, Encoder encoder) implements EditableDocument {
        @Override
        public MessagePatch encode(String editedText) throws EncodeException {
            return encoder.encode(editedText == null ? "" : editedText);
        }
    }

    /** Parses strict JSON (any top-level value); errors name the line and column. */
    public static JsonElement parse(String text, String what) throws EncodeException {
        String label = what == null || what.isEmpty() ? "JSON" : what;
        if (text == null || text.isBlank()) throw new EncodeException(label + " error: the document is empty");
        try (JsonReader r = new JsonReader(new StringReader(text))) {
            r.setStrictness(Strictness.STRICT);
            JsonElement e = JsonParser.parseReader(r);
            JsonToken next = r.peek();
            if (next != JsonToken.END_DOCUMENT) throw new EncodeException(label + " error: unexpected data after the value " + location(r.toString()));
            return e;
        } catch (JsonParseException | IOException | IllegalStateException | NumberFormatException e) {
            throw new EncodeException(label + " error " + describe(e), e);
        }
    }

    /** Parses JSON and returns null instead of throwing. */
    public static JsonElement tryParse(String text) {
        try {
            return parse(text, null);
        } catch (EncodeException e) {
            return null;
        }
    }

    private static String describe(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            String msg = t.getMessage();
            if (msg == null) continue;
            int see = msg.indexOf("\nSee ");
            if (see >= 0) msg = msg.substring(0, see);
            Matcher m = AT.matcher(msg);
            if (m.find()) {
                String what = msg.substring(0, m.start()).strip();
                int colon = what.lastIndexOf("Exception: ");
                if (colon >= 0) what = what.substring(colon + "Exception: ".length());
                return "at line " + m.group(1) + ", column " + m.group(2) + ": " + (what.isEmpty() ? "invalid JSON" : what);
            }
            if (t.getCause() == null) return ": " + msg;
        }
        return ": invalid JSON";
    }

    private static String location(String readerToString) {
        Matcher m = AT.matcher(readerToString);
        return m.find() ? "at line " + m.group(1) + ", column " + m.group(2) : "";
    }

    public static String pretty(JsonElement e) {
        return PRETTY.toJson(e);
    }

    public static String compact(JsonElement e) {
        return COMPACT.toJson(e);
    }

    /** Compact form of a JSON string value (with quotes), e.g. for re-stringifying JSON-in-a-string. */
    public static String quote(String s) {
        return COMPACT.toJson(s);
    }

    // ---------------------------------------------------------------- content encoding

    /** True when the Content-Encoding header names a real encoding (not absent / identity). */
    public static boolean hasEncoding(String contentEncoding) {
        return contentEncoding != null && !contentEncoding.isBlank() && !contentEncoding.trim().equalsIgnoreCase("identity");
    }

    /**
     * Whether a body with this Content-Encoding can be re-encoded after an edit (identity, gzip, x-gzip, deflate) and
     * was actually decodable.
     */
    public static boolean reEncodable(byte[] raw, String contentEncoding) {
        if (!hasEncoding(contentEncoding)) return true;
        String e = contentEncoding.trim().toLowerCase(Locale.ROOT);
        if (!(e.equals("gzip") || e.equals("x-gzip") || e.equals("deflate"))) return false;
        byte[] d = Codecs.decodeContent(raw, contentEncoding);
        return d != null && !Arrays.equals(d, raw);
    }

    /**
     * New raw body for edited decoded content: the original raw bytes when the content is unchanged, otherwise the
     * content re-compressed with the same Content-Encoding.
     */
    public static byte[] reEncode(byte[] newContent, byte[] originalContent, byte[] originalRaw, String contentEncoding) throws EncodeException {
        if (Arrays.equals(newContent, originalContent)) return originalRaw;
        if (!hasEncoding(contentEncoding)) return newContent;
        String e = contentEncoding.trim().toLowerCase(Locale.ROOT);
        if (e.equals("gzip") || e.equals("x-gzip")) return gzip(newContent);
        if (e.equals("deflate")) return deflate(newContent);
        throw new EncodeException("Cannot re-apply Content-Encoding '" + contentEncoding + "'");
    }

    public static byte[] gzip(byte[] b) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length / 2 + 32);
        try (OutputStream z = new GZIPOutputStream(o)) {
            z.write(b);
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
        return o.toByteArray();
    }

    public static byte[] deflate(byte[] b) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length / 2 + 32);
        try (OutputStream z = new DeflaterOutputStream(o)) {
            z.write(b);
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
        return o.toByteArray();
    }
}
