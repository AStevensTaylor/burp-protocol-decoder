package protocoldecoder.script;

import com.google.gson.JsonElement;
import org.mozilla.javascript.BaseFunction;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.ScriptRuntime;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.Undefined;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Native helper functions ({@code codec.*}, {@code log}) exposed to scripts. They only take and return JS values. */
final class JsHelpers {

    @FunctionalInterface
    private interface Impl {
        Object call(Context cx, Scriptable scope, Object[] args) throws IOException;
    }

    private JsHelpers() {
    }

    static void install(Context cx, ScriptableObject global) {
        ScriptableObject codec = (ScriptableObject) cx.newObject(global);
        def(codec, global, "base64Decode", (c, s, a) -> {
            byte[] b = Codecs.base64Decode(str(a, 0));
            if (b == null) throw ScriptRuntime.throwError(c, s, "base64Decode: invalid base64");
            return Codecs.latin1String(b);
        });
        def(codec, global, "base64Encode", (c, s, a) -> Codecs.base64Encode(Codecs.latin1Bytes(str(a, 0))));
        def(codec, global, "hexDecode", (c, s, a) -> {
            String h = str(a, 0).replaceAll("[\\s:]", "");
            try {
                return Codecs.latin1String(HexFormat.of().parseHex(h));
            } catch (IllegalArgumentException e) {
                throw ScriptRuntime.throwError(c, s, "hexDecode: invalid hex");
            }
        });
        def(codec, global, "hexEncode", (c, s, a) -> HexFormat.of().formatHex(Codecs.latin1Bytes(str(a, 0))));
        def(codec, global, "utf8Decode", (c, s, a) -> new String(Codecs.latin1Bytes(str(a, 0)), StandardCharsets.UTF_8));
        def(codec, global, "utf8Encode", (c, s, a) -> Codecs.latin1String(str(a, 0).getBytes(StandardCharsets.UTF_8)));
        def(codec, global, "urlDecode", (c, s, a) -> Codecs.urlDecode(str(a, 0)));
        def(codec, global, "urlEncode", (c, s, a) -> URLEncoder.encode(str(a, 0), StandardCharsets.UTF_8));
        def(codec, global, "parseQuery", (c, s, a) -> {
            Scriptable o = c.newObject(s);
            for (Map.Entry<String, List<String>> e : Codecs.parseQuery(str(a, 0)).entrySet()) {
                ScriptableObject.putProperty(o, e.getKey(), c.newArray(s, e.getValue().toArray()));
            }
            return o;
        });
        def(codec, global, "gunzip", (c, s, a) -> {
            try {
                return Codecs.latin1String(Codecs.gunzip(Codecs.latin1Bytes(str(a, 0))));
            } catch (IOException e) {
                throw ScriptRuntime.throwError(c, s, "gunzip: " + e.getMessage());
            }
        });
        def(codec, global, "inflate", (c, s, a) -> {
            try {
                return Codecs.latin1String(Codecs.inflate(Codecs.latin1Bytes(str(a, 0))));
            } catch (IOException e) {
                throw ScriptRuntime.throwError(c, s, "inflate: " + e.getMessage());
            }
        });
        def(codec, global, "decodeContent", (c, s, a) ->
                Codecs.latin1String(Codecs.decodeContent(Codecs.latin1Bytes(str(a, 0)), a.length > 1 ? str(a, 1) : null)));
        def(codec, global, "parseLenientJson", (c, s, a) -> {
            JsonElement e = JsonTree.parseLenient(str(a, 0));
            if (e == null) throw ScriptRuntime.throwError(c, s, "parseLenientJson: not a valid JSON / JS literal");
            return JsConvert.fromJson(c, s, e, 0);
        });
        codec.sealObject();
        ScriptableObject.defineProperty(global, "codec", codec, ScriptableObject.READONLY | ScriptableObject.PERMANENT);

        BaseFunction log = fn(global, "log", (c, s, a) -> {
            StringBuilder sb = new StringBuilder();
            for (Object o : a) {
                if (sb.length() > 0) sb.append(' ');
                sb.append(o instanceof Scriptable sc && !(o instanceof org.mozilla.javascript.Function) ? JsConvert.stringify(c, s, sc) : Context.toString(o));
            }
            ScriptSandbox.log(c, sb.toString());
            return Undefined.instance;
        });
        ScriptableObject.defineProperty(global, "log", log, ScriptableObject.READONLY | ScriptableObject.PERMANENT);
    }

    private static void def(ScriptableObject target, Scriptable global, String name, Impl impl) {
        target.defineProperty(name, fn(global, name, impl), ScriptableObject.READONLY | ScriptableObject.PERMANENT);
    }

    private static BaseFunction fn(Scriptable global, String name, Impl impl) {
        BaseFunction f = new BaseFunction() {
            @Override
            public Object call(Context cx, Scriptable scope, Scriptable thisObj, Object[] args) {
                try {
                    return impl.call(cx, scope, args);
                } catch (IOException e) {
                    throw ScriptRuntime.throwError(cx, scope, name + ": " + e.getMessage());
                }
            }

            @Override
            public String getFunctionName() {
                return name;
            }
        };
        ScriptRuntime.setFunctionProtoAndParent(f, Context.getCurrentContext(), global);
        f.sealObject();
        return f;
    }

    private static String str(Object[] args, int i) {
        if (i >= args.length || args[i] == null || Undefined.isUndefined(args[i])) return "";
        return Context.toString(args[i]);
    }
}
