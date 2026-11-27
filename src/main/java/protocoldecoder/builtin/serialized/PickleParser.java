package protocoldecoder.builtin.serialized;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Bounded opcode disassembler for Python pickles (similar to {@code pickletools.dis}). Nothing is executed; a tiny
 * model of the stack and memo is kept only so that {@code STACK_GLOBAL} can be resolved to {@code module.attr}.
 */
final class PickleParser {

    private static final int MAX_LINE = 64 * 1024;
    private static final int MAX_SHOWN_ARG = 200;
    private static final int MAX_MODEL = 4096;

    /** Argument encodings. */
    private enum Arg { NONE, U1, U2, I4, U4, U8, LINE, TWO_LINES, BYTES_U1, BYTES_I4, BYTES_U4, BYTES_U8, UNI_U1, UNI_U4, UNI_U8, FLOAT8, LONG_U1, LONG_I4 }

    private record Op(String name, Arg arg) {
    }

    private static final Op[] OPS = new Op[256];

    private static void op(int code, String name, Arg arg) {
        OPS[code] = new Op(name, arg);
    }

    static {
        op('(', "MARK", Arg.NONE);
        op('.', "STOP", Arg.NONE);
        op('0', "POP", Arg.NONE);
        op('1', "POP_MARK", Arg.NONE);
        op('2', "DUP", Arg.NONE);
        op('F', "FLOAT", Arg.LINE);
        op('I', "INT", Arg.LINE);
        op('J', "BININT", Arg.I4);
        op('K', "BININT1", Arg.U1);
        op('L', "LONG", Arg.LINE);
        op('M', "BININT2", Arg.U2);
        op('N', "NONE", Arg.NONE);
        op('P', "PERSID", Arg.LINE);
        op('Q', "BINPERSID", Arg.NONE);
        op('R', "REDUCE", Arg.NONE);
        op('S', "STRING", Arg.LINE);
        op('T', "BINSTRING", Arg.BYTES_I4);
        op('U', "SHORT_BINSTRING", Arg.BYTES_U1);
        op('V', "UNICODE", Arg.LINE);
        op('X', "BINUNICODE", Arg.UNI_U4);
        op('a', "APPEND", Arg.NONE);
        op('b', "BUILD", Arg.NONE);
        op('c', "GLOBAL", Arg.TWO_LINES);
        op('d', "DICT", Arg.NONE);
        op('}', "EMPTY_DICT", Arg.NONE);
        op('e', "APPENDS", Arg.NONE);
        op('g', "GET", Arg.LINE);
        op('h', "BINGET", Arg.U1);
        op('i', "INST", Arg.TWO_LINES);
        op('j', "LONG_BINGET", Arg.U4);
        op('l', "LIST", Arg.NONE);
        op(']', "EMPTY_LIST", Arg.NONE);
        op('o', "OBJ", Arg.NONE);
        op('p', "PUT", Arg.LINE);
        op('q', "BINPUT", Arg.U1);
        op('r', "LONG_BINPUT", Arg.U4);
        op('s', "SETITEM", Arg.NONE);
        op('t', "TUPLE", Arg.NONE);
        op(')', "EMPTY_TUPLE", Arg.NONE);
        op('u', "SETITEMS", Arg.NONE);
        op('G', "BINFLOAT", Arg.FLOAT8);
        op(0x80, "PROTO", Arg.U1);
        op(0x81, "NEWOBJ", Arg.NONE);
        op(0x82, "EXT1", Arg.U1);
        op(0x83, "EXT2", Arg.U2);
        op(0x84, "EXT4", Arg.I4);
        op(0x85, "TUPLE1", Arg.NONE);
        op(0x86, "TUPLE2", Arg.NONE);
        op(0x87, "TUPLE3", Arg.NONE);
        op(0x88, "NEWTRUE", Arg.NONE);
        op(0x89, "NEWFALSE", Arg.NONE);
        op(0x8a, "LONG1", Arg.LONG_U1);
        op(0x8b, "LONG4", Arg.LONG_I4);
        op('B', "BINBYTES", Arg.BYTES_U4);
        op('C', "SHORT_BINBYTES", Arg.BYTES_U1);
        op(0x8c, "SHORT_BINUNICODE", Arg.UNI_U1);
        op(0x8d, "BINUNICODE8", Arg.UNI_U8);
        op(0x8e, "BINBYTES8", Arg.BYTES_U8);
        op(0x8f, "EMPTY_SET", Arg.NONE);
        op(0x90, "ADDITEMS", Arg.NONE);
        op(0x91, "FROZENSET", Arg.NONE);
        op(0x92, "NEWOBJ_EX", Arg.NONE);
        op(0x93, "STACK_GLOBAL", Arg.NONE);
        op(0x94, "MEMOIZE", Arg.NONE);
        op(0x95, "FRAME", Arg.U8);
        op(0x96, "BYTEARRAY8", Arg.BYTES_U8);
        op(0x97, "NEXT_BUFFER", Arg.NONE);
        op(0x98, "READONLY_BUFFER", Arg.NONE);
    }

    /** True if the byte is a known opcode (used by the sniffer to reject random 0x80 0x0N prefixes). */
    static boolean isOpcode(int b) {
        return b >= 0 && b < 256 && OPS[b] != null;
    }

    private static final Object OTHER = new Object();

    private final Bin in;
    private final ParseOutput.Budget budget;
    private final ParseOutput out = new ParseOutput("Disassembly");
    /** Recently pushed values: Strings for string pushes, OTHER for anything else. */
    private final Deque<Object> stack = new ArrayDeque<>();
    private final Map<Long, Object> memo = new HashMap<>();
    private long memoNext;
    private int calls;
    private final List<String> callOps = new ArrayList<>();
    /** Strings used as STACK_GLOBAL module/attribute names (not offered as insertion points). */
    private final java.util.Set<String> globalOperands = new java.util.HashSet<>();

    private PickleParser(byte[] data, ParseOutput.Budget budget) {
        this.in = new Bin(data);
        this.budget = budget;
    }

    static ParseOutput parse(byte[] data, ParseOutput.Budget budget) {
        PickleParser p = new PickleParser(data, budget);
        p.run();
        return p.out;
    }

    private void run() {
        out.typeNoun = "globals";
        DecodedNode dis = out.structure;
        boolean stopped = false;
        try {
            while (in.hasMore()) {
                int at = in.pos();
                int code = in.u8();
                Op op = OPS[code];
                if (op == null) throw new Bin.FormatException(String.format("unknown opcode 0x%02x at offset %d", code, at));
                String arg = readArg(op, code);
                budget.add(dis, DecodedNode.leaf(String.format("%5d", at), op.name + (arg.isEmpty() ? "" : " " + arg)));
                if (code == '.') {
                    stopped = true;
                    break;
                }
            }
            if (!stopped) out.stop("no STOP opcode before the end of the data (truncated pickle?)");
            else if (in.hasMore()) out.notes.add(in.remaining() + " bytes after STOP");
        } catch (Bin.FormatException e) {
            out.stop(e.getMessage());
        }
        if (!globalOperands.isEmpty()) out.spans.removeIf(sp -> globalOperands.contains(sp.value()));
        if (calls > 0) {
            out.notes.add("pickle invokes callables on load: " + calls + " × " + String.join("/", new java.util.LinkedHashSet<>(callOps)));
        }
    }

    private String readArg(Op op, int code) throws Bin.FormatException {
        int opAt = in.pos() - 1;
        String shown;
        switch (op.arg) {
            case NONE -> {
                shown = "";
                model(code, null);
            }
            case U1 -> {
                long v = in.u8();
                shown = Long.toString(v);
                model(code, v);
            }
            case U2 -> {
                long v = in.u16le();
                shown = Long.toString(v);
                model(code, v);
            }
            case I4 -> {
                long v = in.s32le();
                shown = Long.toString(v);
                model(code, v);
            }
            case U4 -> {
                long v = in.u32le();
                shown = Long.toString(v);
                model(code, v);
            }
            case U8 -> {
                int lengthAt = in.pos();
                long v = in.s64le();
                if (code == 0x95 && out.frames.size() < ParseOutput.MAX_SPANS) out.frames.add(new ParseOutput.Frame(lengthAt, in.pos(), v));
                shown = Long.toUnsignedString(v);
                model(code, v);
            }
            case FLOAT8 -> {
                shown = Double.toString(Double.longBitsToDouble(in.s64be()));
                push(OTHER);
            }
            case LINE -> {
                String line = line();
                shown = quote(line);
                if (code == 'S' || code == 'V') push(unquote(line));
                else if (code == 'g') push(memo.getOrDefault(parseLong(line), OTHER));
                else if (code == 'p') memoPut(parseLong(line));
                else push(OTHER);
            }
            case TWO_LINES -> {
                String module = line();
                String name = line();
                String global = module + "." + name;
                shown = global;
                out.type(global);
                if (code == 'i') call("INST");
                push(OTHER);
            }
            case BYTES_U1, BYTES_I4, BYTES_U4, BYTES_U8 -> {
                long len = switch (op.arg) {
                    case BYTES_U1 -> in.u8();
                    case BYTES_I4 -> in.s32le();
                    case BYTES_U4 -> in.u32le();
                    default -> in.s64le();
                };
                byte[] b = in.bytes(len);
                if (code == 'T' || code == 'U') {
                    String s = new String(b, StandardCharsets.ISO_8859_1);
                    shown = quote(s);
                    push(s);
                } else {
                    shown = "b[" + b.length + "] " + Codecs.hexPreview(b, 32);
                    push(OTHER);
                }
            }
            case UNI_U1, UNI_U4, UNI_U8 -> {
                long len = switch (op.arg) {
                    case UNI_U1 -> in.u8();
                    case UNI_U4 -> in.u32le();
                    default -> in.s64le();
                };
                String s = in.utf8(len);
                out.span(opAt, in.pos(), s, List.of("$", "[" + out.spans.size() + "]"), 'P');
                shown = quote(s);
                push(s);
            }
            case LONG_U1, LONG_I4 -> {
                long len = op.arg == Arg.LONG_U1 ? in.u8() : in.s32le();
                byte[] b = in.bytes(len);
                shown = littleEndianSigned(b);
                push(OTHER);
            }
            default -> throw new IllegalStateException();
        }
        return shown;
    }

    /** Minimal stack/memo model, just enough to resolve STACK_GLOBAL operands. */
    private void model(int code, Long arg) {
        switch (code) {
            case 0x80 -> out.structure.put("protocol", arg == null ? null : arg.toString());
            case 0x95 -> { } // FRAME
            case 'q', 'r' -> memoPut(arg);
            case 0x94 -> memoPut(memoNext);
            case 'h', 'j' -> push(memo.getOrDefault(arg, OTHER));
            case '0' -> pop();
            case '2' -> push(stack.isEmpty() ? OTHER : stack.peek());
            case 0x93 -> {
                Object name = pop();
                Object module = pop();
                String global = (module instanceof String m ? m : "?") + "." + (name instanceof String n ? n : "?");
                if (module instanceof String m) globalOperands.add(m);
                if (name instanceof String n) globalOperands.add(n);
                out.type(global);
                push(OTHER);
            }
            case 'R' -> call("REDUCE");
            case 0x81 -> call("NEWOBJ");
            case 0x92 -> call("NEWOBJ_EX");
            case 'o' -> call("OBJ");
            case '(', '1', 'a', 'b', 'd', 'e', 'l', 's', 't', 'u', 0x85, 0x86, 0x87, 0x90, 0x91, 0x97, 0x98, '.', 'Q' -> {
                if (code != '(' && code != '.') {
                    // collection-building ops consume the recent values; collapse to a placeholder
                    push(OTHER);
                }
            }
            default -> push(OTHER);
        }
    }

    private void call(String opName) {
        calls++;
        if (callOps.size() < 16) callOps.add(opName);
    }

    private void memoPut(Long idx) {
        if (idx == null) return;
        if (memo.size() < MAX_MODEL) memo.put(idx, stack.isEmpty() ? OTHER : stack.peek());
        memoNext = Math.max(memoNext, idx + 1);
    }

    private void push(Object o) {
        stack.push(o);
        if (stack.size() > MAX_MODEL) stack.removeLast();
    }

    private Object pop() {
        return stack.isEmpty() ? OTHER : stack.pop();
    }

    private String line() throws Bin.FormatException {
        StringBuilder sb = new StringBuilder();
        int start = in.pos();
        while (true) {
            if (in.pos() - start > MAX_LINE) throw new Bin.FormatException("line argument too long at offset " + start);
            int c = in.u8();
            if (c == '\n') break;
            sb.append((char) c);
        }
        return sb.toString();
    }

    private static Long parseLong(String s) {
        try {
            return Long.parseLong(s.strip());
        } catch (NumberFormatException e) {
            return -1L;
        }
    }

    private static String unquote(String s) {
        String t = s.strip();
        if (t.length() >= 2 && (t.charAt(0) == '\'' || t.charAt(0) == '"') && t.charAt(t.length() - 1) == t.charAt(0)) {
            return t.substring(1, t.length() - 1);
        }
        return t;
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder("'");
        String t = Codecs.truncate(s, MAX_SHOWN_ARG);
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '\n') sb.append("\\n");
            else if (c < 0x20 || c == 0x7f) sb.append(String.format("\\x%02x", (int) c));
            else sb.append(c);
        }
        return sb.append('\'').toString();
    }

    private static String littleEndianSigned(byte[] b) {
        if (b.length == 0) return "0";
        if (b.length > 64) return "long of " + b.length + " bytes " + Codecs.hexPreview(b, 16);
        byte[] be = new byte[b.length];
        for (int i = 0; i < b.length; i++) be[i] = b[b.length - 1 - i];
        String v = new java.math.BigInteger(be).toString();
        return Codecs.truncate(v, MAX_SHOWN_ARG);
    }
}
