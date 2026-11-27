package protocoldecoder.builtin.blazor;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.edit.EncodeException;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Lossless MessagePack ↔ JSON mapping for editing:
 * <ul>
 *   <li>nil, booleans, strings and arrays map directly; integers are JSON integers (any width, uint64 included);</li>
 *   <li>float64 is a JSON number that always has a fraction or exponent ({@code 1.0}); float32 is {@code {"$f32": 1.5}};
 *       NaN/±Infinity are {@code {"$f64": "NaN"}} / {@code {"$f32": "Infinity"}};</li>
 *   <li>bin is {@code {"$bin": "<base64>"}}, ext is {@code {"$ext": [type, "<base64>"]}}, a str that is not valid UTF-8
 *       is {@code {"$strbin": "<base64>"}};</li>
 *   <li>maps with unique string keys are JSON objects; any other map (non-string or duplicate keys, or one that would
 *       look like a tag above) is {@code {"$map": [[key, value], …]}}.</li>
 * </ul>
 * Encoding always picks the smallest MessagePack format for each value.
 */
final class MsgPackJson {

    static final Set<String> TAGS = Set.of("$bin", "$ext", "$f32", "$f64", "$map", "$strbin");
    private static final int MAX_DEPTH = 64;

    private MsgPackJson() {
    }

    // ================================================================== MessagePack → JSON

    /** Converts exactly one value spanning {@code [start, end)}. */
    static JsonElement toJson(byte[] b, int start, int end) throws MsgPack.FormatException {
        Reader r = new Reader(b, start, end);
        JsonElement e = r.read(0);
        if (r.pos != end) throw new MsgPack.FormatException((end - r.pos) + " trailing bytes after the value");
        return e;
    }

    private static final class Reader {
        final byte[] b;
        int pos;
        final int end;

        Reader(byte[] b, int pos, int end) {
            this.b = b;
            this.pos = pos;
            this.end = end;
        }

        JsonElement read(int depth) throws MsgPack.FormatException {
            if (depth > MAX_DEPTH) throw new MsgPack.FormatException("nested too deep");
            int t = u8();
            if (t <= 0x7f) return new JsonPrimitive(t);
            if (t >= 0xe0) return new JsonPrimitive((int) (byte) t);
            if ((t & 0xf0) == 0x80) return map(t & 0x0f, depth);
            if ((t & 0xf0) == 0x90) return array(t & 0x0f, depth);
            if ((t & 0xe0) == 0xa0) return str(t & 0x1f);
            return switch (t) {
                case 0xc0 -> JsonNull.INSTANCE;
                case 0xc2 -> new JsonPrimitive(false);
                case 0xc3 -> new JsonPrimitive(true);
                case 0xc4 -> tag("$bin", b64(bytes(u(1))));
                case 0xc5 -> tag("$bin", b64(bytes(u(2))));
                case 0xc6 -> tag("$bin", b64(bytes(len32())));
                case 0xc7 -> ext(u(1));
                case 0xc8 -> ext(u(2));
                case 0xc9 -> ext(len32());
                case 0xca -> f32(Float.intBitsToFloat((int) u(4)));
                case 0xcb -> f64(Double.longBitsToDouble(u(8)));
                case 0xcc -> new JsonPrimitive(u(1));
                case 0xcd -> new JsonPrimitive(u(2));
                case 0xce -> new JsonPrimitive(u(4));
                case 0xcf -> {
                    long v = u(8);
                    yield v >= 0 ? new JsonPrimitive(v) : new JsonPrimitive(new BigInteger(Long.toUnsignedString(v)));
                }
                case 0xd0 -> new JsonPrimitive((long) (byte) u(1));
                case 0xd1 -> new JsonPrimitive((long) (short) u(2));
                case 0xd2 -> new JsonPrimitive((long) (int) u(4));
                case 0xd3 -> new JsonPrimitive(u(8));
                case 0xd4 -> ext(1);
                case 0xd5 -> ext(2);
                case 0xd6 -> ext(4);
                case 0xd7 -> ext(8);
                case 0xd8 -> ext(16);
                case 0xd9 -> str(u(1));
                case 0xda -> str(u(2));
                case 0xdb -> str(len32());
                case 0xdc -> array((int) u(2), depth);
                case 0xdd -> array(len32(), depth);
                case 0xde -> map((int) u(2), depth);
                case 0xdf -> map(len32(), depth);
                default -> throw new MsgPack.FormatException(String.format("invalid type byte 0x%02x at %d", t, pos - 1));
            };
        }

        JsonElement array(int n, int depth) throws MsgPack.FormatException {
            if (n > end - pos) throw new MsgPack.FormatException("array length " + n + " exceeds data");
            JsonArray a = new JsonArray();
            for (int i = 0; i < n; i++) a.add(read(depth + 1));
            return a;
        }

        JsonElement map(int n, int depth) throws MsgPack.FormatException {
            if (n > (end - pos) / 2) throw new MsgPack.FormatException("map length " + n + " exceeds data");
            JsonArray pairs = new JsonArray();
            boolean plain = true;
            Set<String> keys = new HashSet<>();
            for (int i = 0; i < n; i++) {
                JsonElement k = read(depth + 1);
                JsonElement v = read(depth + 1);
                JsonArray pair = new JsonArray();
                pair.add(k);
                pair.add(v);
                pairs.add(pair);
                if (!(k.isJsonPrimitive() && k.getAsJsonPrimitive().isString()) || !keys.add(k.getAsString())) plain = false;
            }
            if (plain && n == 1 && TAGS.contains(keys.iterator().next())) plain = false;
            if (!plain) return tag("$map", pairs);
            JsonObject o = new JsonObject();
            for (JsonElement p : pairs) o.add(p.getAsJsonArray().get(0).getAsString(), p.getAsJsonArray().get(1));
            return o;
        }

        JsonElement str(long n) throws MsgPack.FormatException {
            byte[] raw = bytes(n);
            try {
                String s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
                return new JsonPrimitive(s);
            } catch (CharacterCodingException e) {
                return tag("$strbin", b64(raw));
            }
        }

        JsonElement ext(long n) throws MsgPack.FormatException {
            int type = (byte) u8();
            JsonArray a = new JsonArray();
            a.add(type);
            a.add(b64(bytes(n)));
            return tag("$ext", a);
        }

        byte[] bytes(long n) throws MsgPack.FormatException {
            if (n < 0 || n > end - pos) throw new MsgPack.FormatException("unexpected end of data");
            byte[] out = new byte[(int) n];
            System.arraycopy(b, pos, out, 0, (int) n);
            pos += (int) n;
            return out;
        }

        int u8() throws MsgPack.FormatException {
            if (pos >= end) throw new MsgPack.FormatException("unexpected end of data");
            return b[pos++] & 0xff;
        }

        long u(int n) throws MsgPack.FormatException {
            long v = 0;
            for (int i = 0; i < n; i++) v = (v << 8) | u8();
            return v;
        }

        int len32() throws MsgPack.FormatException {
            long v = u(4);
            if (v > Integer.MAX_VALUE) throw new MsgPack.FormatException("length too large");
            return (int) v;
        }
    }

    private static JsonElement f64(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) return tag("$f64", new JsonPrimitive(Double.toString(d)));
        return new JsonPrimitive(d);
    }

    private static JsonElement f32(float f) {
        if (Float.isNaN(f) || Float.isInfinite(f)) return tag("$f32", new JsonPrimitive(Float.toString(f)));
        return tag("$f32", new JsonPrimitive(f));
    }

    private static JsonObject tag(String name, JsonElement v) {
        JsonObject o = new JsonObject();
        o.add(name, v);
        return o;
    }

    private static JsonPrimitive b64(byte[] b) {
        return new JsonPrimitive(Base64.getEncoder().encodeToString(b));
    }

    /** True if the value contains a bin anywhere (for titles). */
    static boolean containsBin(JsonElement e) {
        if (e == null) return false;
        if (e.isJsonArray()) {
            for (JsonElement x : e.getAsJsonArray()) if (containsBin(x)) return true;
        } else if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            if (o.size() == 1 && o.has("$bin")) return true;
            for (Map.Entry<String, JsonElement> en : o.entrySet()) if (containsBin(en.getValue())) return true;
        }
        return false;
    }

    // ================================================================== JSON → MessagePack

    static byte[] fromJson(JsonElement e, String path) throws EncodeException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        write(o, e, path, 0);
        return o.toByteArray();
    }

    private static void write(ByteArrayOutputStream o, JsonElement e, String path, int depth) throws EncodeException {
        if (depth > MAX_DEPTH) throw new EncodeException(path + ": nested too deep");
        if (e == null || e.isJsonNull()) {
            MsgPackWriter.nil(o);
        } else if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            MsgPackWriter.arrayHeader(o, a.size());
            for (int i = 0; i < a.size(); i++) write(o, a.get(i), path + "[" + i + "]", depth + 1);
        } else if (e.isJsonObject()) {
            JsonObject obj = e.getAsJsonObject();
            if (obj.size() == 1 && TAGS.contains(obj.keySet().iterator().next())) {
                tagged(o, obj.keySet().iterator().next(), obj.entrySet().iterator().next().getValue(), path, depth);
                return;
            }
            MsgPackWriter.mapHeader(o, obj.size());
            for (Map.Entry<String, JsonElement> en : obj.entrySet()) {
                MsgPackWriter.strBytes(o, en.getKey().getBytes(StandardCharsets.UTF_8));
                write(o, en.getValue(), path + "." + en.getKey(), depth + 1);
            }
        } else {
            JsonPrimitive p = e.getAsJsonPrimitive();
            if (p.isBoolean()) MsgPackWriter.bool(o, p.getAsBoolean());
            else if (p.isString()) MsgPackWriter.strBytes(o, p.getAsString().getBytes(StandardCharsets.UTF_8));
            else number(o, p.getAsNumber().toString(), path);
        }
    }

    private static void number(ByteArrayOutputStream o, String text, String path) throws EncodeException {
        if (text.matches("-?[0-9]+")) {
            BigInteger v = new BigInteger(text);
            if (v.bitLength() > 64 || (v.signum() < 0 && v.bitLength() > 63)) {
                throw new EncodeException(path + ": integer " + text + " is out of the MessagePack range (int64 / uint64)");
            }
            MsgPackWriter.integer(o, v);
            return;
        }
        try {
            double d = Double.parseDouble(text);
            if (Double.isInfinite(d)) throw new EncodeException(path + ": number " + text + " is out of the float64 range");
            MsgPackWriter.float64(o, d);
        } catch (NumberFormatException ex) {
            throw new EncodeException(path + ": invalid number " + text);
        }
    }

    private static void tagged(ByteArrayOutputStream o, String tag, JsonElement v, String path, int depth) throws EncodeException {
        String at = path + "." + tag;
        switch (tag) {
            case "$bin" -> MsgPackWriter.bin(o, base64(v, at));
            case "$strbin" -> MsgPackWriter.strBytes(o, base64(v, at));
            case "$ext" -> {
                if (!v.isJsonArray() || v.getAsJsonArray().size() != 2) throw new EncodeException(at + " must be [type, \"<base64>\"]");
                JsonElement t = v.getAsJsonArray().get(0);
                int type;
                try {
                    type = t.getAsJsonPrimitive().isNumber() ? Integer.parseInt(t.getAsString()) : Integer.MIN_VALUE;
                } catch (RuntimeException ex) {
                    type = Integer.MIN_VALUE;
                }
                if (type < -128 || type > 127) throw new EncodeException(at + ": the ext type must be an integer from -128 to 127");
                MsgPackWriter.ext(o, type, base64(v.getAsJsonArray().get(1), at));
            }
            case "$f32", "$f64" -> {
                double d = floatValue(v, at);
                if (tag.equals("$f32")) MsgPackWriter.float32(o, (float) d);
                else MsgPackWriter.float64(o, d);
            }
            case "$map" -> {
                if (!v.isJsonArray()) throw new EncodeException(at + " must be an array of [key, value] pairs");
                JsonArray pairs = v.getAsJsonArray();
                MsgPackWriter.mapHeader(o, pairs.size());
                for (int i = 0; i < pairs.size(); i++) {
                    JsonElement p = pairs.get(i);
                    if (!p.isJsonArray() || p.getAsJsonArray().size() != 2) throw new EncodeException(at + "[" + i + "] must be a [key, value] pair");
                    write(o, p.getAsJsonArray().get(0), at + "[" + i + "][0]", depth + 1);
                    write(o, p.getAsJsonArray().get(1), at + "[" + i + "][1]", depth + 1);
                }
            }
            default -> throw new EncodeException(at + ": unknown tag");
        }
    }

    private static double floatValue(JsonElement v, String at) throws EncodeException {
        if (v.isJsonPrimitive()) {
            JsonPrimitive p = v.getAsJsonPrimitive();
            String s = p.getAsString();
            switch (s) {
                case "NaN" -> { return Double.NaN; }
                case "Infinity" -> { return Double.POSITIVE_INFINITY; }
                case "-Infinity" -> { return Double.NEGATIVE_INFINITY; }
                default -> { }
            }
            if (p.isNumber()) {
                try {
                    return Double.parseDouble(s);
                } catch (NumberFormatException ignored) {
                    // fall through
                }
            }
        }
        throw new EncodeException(at + " must be a number, \"NaN\", \"Infinity\" or \"-Infinity\"");
    }

    private static byte[] base64(JsonElement v, String at) throws EncodeException {
        if (v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) {
            try {
                return Base64.getDecoder().decode(v.getAsString().replaceAll("\\s+", ""));
            } catch (IllegalArgumentException ignored) {
                // fall through
            }
        }
        throw new EncodeException(at + " must be a base64 string");
    }
}
