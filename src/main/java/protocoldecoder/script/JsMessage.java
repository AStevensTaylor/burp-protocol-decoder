package protocoldecoder.script;

import org.mozilla.javascript.BaseFunction;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.ScriptRuntime;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The read-only {@code msg} object handed to scripts. Properties are computed lazily (large bodies are only turned into
 * strings if the script reads them) and only JavaScript-native values are ever returned.
 */
final class JsMessage extends ScriptableObject {

    /** Plain snapshot of the message, size-limited, safe to hand to the worker thread. */
    record Data(MessageContext m, int maxBody) {
        byte[] cap(byte[] b) {
            return b.length > maxBody ? Arrays.copyOf(b, maxBody) : b;
        }

        boolean truncated() {
            return m.requestBody().length > maxBody || m.responseBody().length > maxBody || m.body().length > maxBody;
        }
    }

    private static final String[] IDS = {
            "kind", "isRequest", "isResponse", "isWebSocket", "method", "url", "host", "path", "query", "statusCode",
            "contentType", "headers", "requestHeaders", "responseHeaders", "header", "requestHeader", "responseHeader",
            "body", "bodyText", "requestBody", "requestBodyText", "responseBody", "responseBodyText", "queryParams",
            "formParams", "websocketDirection", "truncated"};

    private final Data data;
    private final Map<String, Object> cache = new HashMap<>();

    JsMessage(Data data, Scriptable scope) {
        this.data = data;
        setParentScope(scope);
        setPrototype(ScriptableObject.getObjectPrototype(scope));
    }

    @Override
    public String getClassName() {
        return "Message";
    }

    @Override
    public boolean has(String name, Scriptable start) {
        return Arrays.asList(IDS).contains(name) || super.has(name, start);
    }

    @Override
    public Object[] getIds() {
        return Arrays.copyOf(IDS, IDS.length, Object[].class);
    }

    @Override
    public void put(String name, Scriptable start, Object value) {
        // read-only: silently ignore like a frozen object in sloppy mode
    }

    @Override
    public void delete(String name) {
        // read-only
    }

    @Override
    public Object get(String name, Scriptable start) {
        if (cache.containsKey(name)) return cache.get(name);
        Object v = compute(name);
        if (v == NOT_FOUND) return super.get(name, start);
        cache.put(name, v);
        return v;
    }

    private Object compute(String name) {
        MessageContext m = data.m();
        Scriptable scope = getParentScope();
        return switch (name) {
            case "kind" -> m.kind().name().toLowerCase();
            case "isRequest" -> m.kind() == MessageKind.REQUEST;
            case "isResponse" -> m.kind() == MessageKind.RESPONSE;
            case "isWebSocket" -> m.kind() == MessageKind.WEBSOCKET;
            case "method" -> m.method();
            case "url" -> m.url();
            case "host" -> m.host();
            case "path" -> m.path();
            case "query" -> m.query();
            case "statusCode" -> m.statusCode() == null ? null : (Object) m.statusCode().doubleValue();
            case "contentType" -> m.contentType();
            case "headers" -> headers(m.headers(), scope);
            case "requestHeaders" -> headers(m.requestHeaders(), scope);
            case "responseHeaders" -> headers(m.responseHeaders(), scope);
            case "header" -> headerFn("header", m.headers(), scope);
            case "requestHeader" -> headerFn("requestHeader", m.requestHeaders(), scope);
            case "responseHeader" -> headerFn("responseHeader", m.responseHeaders(), scope);
            case "body" -> Codecs.latin1String(data.cap(m.body()));
            case "bodyText" -> new String(data.cap(m.body()), StandardCharsets.UTF_8);
            case "requestBody" -> Codecs.latin1String(data.cap(m.requestBody()));
            case "requestBodyText" -> new String(data.cap(m.requestBody()), StandardCharsets.UTF_8);
            case "responseBody" -> Codecs.latin1String(data.cap(m.responseBody()));
            case "responseBodyText" -> new String(data.cap(m.responseBody()), StandardCharsets.UTF_8);
            case "queryParams" -> firstValues(m.queryParameters(), scope);
            case "formParams" -> firstValues(m.formParameters(), scope);
            case "websocketDirection" -> m.webSocketDirection();
            case "truncated" -> data.truncated();
            default -> NOT_FOUND;
        };
    }

    private static Scriptable headers(List<Header> headers, Scriptable scope) {
        Context cx = Context.getCurrentContext();
        Object[] arr = new Object[headers.size()];
        for (int i = 0; i < arr.length; i++) {
            Scriptable o = cx.newObject(scope);
            ScriptableObject.putProperty(o, "name", headers.get(i).name());
            ScriptableObject.putProperty(o, "value", headers.get(i).value());
            arr[i] = o;
        }
        return cx.newArray(scope, arr);
    }

    private static Scriptable firstValues(Map<String, List<String>> params, Scriptable scope) {
        Scriptable o = Context.getCurrentContext().newObject(scope);
        params.forEach((k, v) -> {
            if (!v.isEmpty()) ScriptableObject.putProperty(o, k, v.get(0));
        });
        return o;
    }

    private static BaseFunction headerFn(String fnName, List<Header> headers, Scriptable scope) {
        BaseFunction f = new BaseFunction() {
            @Override
            public Object call(Context cx, Scriptable s, Scriptable thisObj, Object[] args) {
                if (args.length == 0) return null;
                String want = Context.toString(args[0]);
                for (Header h : headers) if (h.name().equalsIgnoreCase(want)) return h.value();
                return null;
            }

            @Override
            public String getFunctionName() {
                return fnName;
            }

            @Override
            public int getArity() {
                return 1;
            }
        };
        ScriptRuntime.setFunctionProtoAndParent(f, Context.getCurrentContext(), scope);
        return f;
    }
}
