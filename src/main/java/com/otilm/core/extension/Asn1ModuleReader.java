package com.otilm.core.extension;

import com.otilm.api.exception.ValidationException;
import com.otilm.core.extension.ExtensionType.Choice;
import com.otilm.core.extension.ExtensionType.Member;
import com.otilm.core.extension.ExtensionType.Opaque;
import com.otilm.core.extension.ExtensionType.Primitive;
import com.otilm.core.extension.ExtensionType.Range;
import com.otilm.core.extension.ExtensionType.Repeated;
import com.otilm.core.extension.ExtensionType.Scalar;
import com.otilm.core.extension.ExtensionType.Structure;
import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the ASN.1 module an operator registers for an extension into the type the platform encodes against.
 *
 * <p>
 * The subset is the one certificate extensions are written in: SEQUENCE, SET, their OF forms, CHOICE, context tags, the
 * built-in types X.509 uses, and SIZE and value-range constraints. Anything else is refused by name, so an operator
 * learns their module needs narrowing rather than discovering later that a construct was quietly dropped.
 */
public final class Asn1ModuleReader {

    private static final Map<String, Primitive> BUILT_IN = Map
            .ofEntries(Map.entry("BOOLEAN", Primitive.BOOLEAN), Map.entry("INTEGER", Primitive.INTEGER),
                    Map.entry("NULL", Primitive.NULL), Map.entry("UTF8String", Primitive.UTF8_STRING),
                    Map.entry("IA5String", Primitive.IA5_STRING),
                    Map.entry("PrintableString", Primitive.PRINTABLE_STRING),
                    Map.entry("GeneralizedTime", Primitive.GENERALIZED_TIME));

    private final List<String> tokens = new ArrayList<>();
    private int at;
    private boolean implicitTags = true;
    private final Map<String, Node> assignments = new LinkedHashMap<>();
    private String rootName;

    /** The parse tree, before type references are resolved. */
    private static final class Node {

        private String kind;
        private Primitive primitive;
        private String reference;
        private List<Node> members;
        private Node element;
        private boolean set;
        private Range valueRange;
        private List<Range> sizes = List.of();
        private String name;
        private Integer tag;
        private Boolean explicit;
        private boolean optional;
        private Object defaultValue;
    }

    private Asn1ModuleReader(String module) {
        tokenise(module);
    }

    /** The type of the module's first assignment, which is the extension's own. */
    public static ExtensionType read(String module) {
        if (module == null || module.isBlank()) {
            throw new ValidationException("The extension's ASN.1 module is empty");
        }
        Asn1ModuleReader reader = new Asn1ModuleReader(module);
        reader.module();
        if (reader.rootName == null) {
            throw new ValidationException("The extension's ASN.1 module assigns no type");
        }
        return reader
                .resolve(reader.assignments.get(reader.rootName), null, new ArrayDeque<>(List.of(reader.rootName)));
    }

    // ---------- lexing ----------

    private void tokenise(String module) {
        StringBuilder word = new StringBuilder();
        for (String line : module.split("\n")) {
            int comment = line.indexOf("--");
            String text = comment < 0 ? line : line.substring(0, comment);
            for (int i = 0; i < text.length(); i++) {
                char ch = text.charAt(i);
                if (Character.isLetterOrDigit(ch) || ch == '-' || ch == '_') {
                    word.append(ch);
                    continue;
                }
                flush(word);
                if (ch == '.' && text.startsWith("..", i)) {
                    tokens.add("..");
                    i++;
                } else if (ch == ':' && text.startsWith("::=", i)) {
                    tokens.add("::=");
                    i += 2;
                } else if (!Character.isWhitespace(ch)) {
                    tokens.add(String.valueOf(ch));
                }
            }
            flush(word);
        }
    }

    private void flush(StringBuilder word) {
        if (word.length() > 0) {
            tokens.add(word.toString());
            word.setLength(0);
        }
    }

    private String peek() {
        return at < tokens.size() ? tokens.get(at) : "";
    }

    private String take() {
        if (at >= tokens.size()) {
            throw new ValidationException("The extension's ASN.1 module ends unexpectedly");
        }
        return tokens.get(at++);
    }

    private boolean accept(String token) {
        if (peek().equals(token)) {
            at++;
            return true;
        }
        return false;
    }

    private void require(String token) {
        if (!accept(token)) {
            throw new ValidationException(
                    "The extension's ASN.1 module has '%s' where '%s' belongs".formatted(peek(), token));
        }
    }

    // ---------- parsing ----------

    private void module() {
        take();
        while (!peek().equals("BEGIN")) {
            if (peek().equals("EXPLICIT")) {
                implicitTags = false;
            }
            take();
        }
        require("BEGIN");
        while (!peek().equals("END") && at < tokens.size()) {
            String name = take();
            require("::=");
            assignments.put(name, type());
            if (rootName == null) {
                rootName = name;
            }
        }
    }

    private Node type() {
        Node node = new Node();
        String token = take();
        switch (token) {
            case "SEQUENCE", "SET" -> collection(node, token.equals("SET"));
            case "CHOICE" -> {
                node.kind = "choice";
                node.members = members();
            }
            case "OCTET" -> {
                require("STRING");
                node.kind = "scalar";
                node.primitive = Primitive.OCTET_STRING;
            }
            case "BIT" -> {
                require("STRING");
                node.kind = "scalar";
                node.primitive = Primitive.BIT_STRING;
            }
            case "OBJECT" -> {
                require("IDENTIFIER");
                node.kind = "scalar";
                node.primitive = Primitive.OID;
            }
            case "ANY" -> {
                if (accept("DEFINED")) {
                    require("BY");
                    take();
                }
                node.kind = "opaque";
                node.reference = "ANY";
            }
            default -> named(node, token);
        }
        if (peek().equals("(")) {
            constraint(node);
        }
        return node;
    }

    private void named(Node node, String token) {
        Primitive builtIn = BUILT_IN.get(token);
        if (builtIn != null) {
            node.kind = "scalar";
            node.primitive = builtIn;
            return;
        }
        if (!Character.isUpperCase(token.charAt(0))) {
            throw new ValidationException(
                    "The extension's ASN.1 module uses '%s', which this platform does not support".formatted(token));
        }
        node.kind = "reference";
        node.reference = token;
    }

    private void collection(Node node, boolean set) {
        node.set = set;
        if (peek().equals("SIZE") || peek().equals("(")) {
            constraint(node);
        }
        if (accept("OF")) {
            node.kind = "repeated";
            node.element = type();
            return;
        }
        node.kind = "structure";
        node.members = members();
    }

    private List<Node> members() {
        List<Node> out = new ArrayList<>();
        require("{");
        do {
            String name = take();
            Integer tag = null;
            Boolean explicit = null;
            if (accept("[")) {
                tag = number(take());
                require("]");
                if (accept("EXPLICIT")) {
                    explicit = true;
                } else if (accept("IMPLICIT")) {
                    explicit = false;
                }
            }
            Node member = type();
            member.name = name;
            member.tag = tag;
            member.explicit = explicit;
            if (accept("OPTIONAL")) {
                member.optional = true;
            } else if (accept("DEFAULT")) {
                member.defaultValue = literal(take());
            }
            out.add(member);
        } while (accept(","));
        require("}");
        return out;
    }

    private static int number(String token) {
        try {
            return Integer.parseInt(token);
        } catch (NumberFormatException e) {
            throw new ValidationException(
                    "The extension's ASN.1 module has '%s' where a number belongs".formatted(token));
        }
    }

    private static Object literal(String token) {
        if (token.equals("TRUE")) {
            return Boolean.TRUE;
        }
        if (token.equals("FALSE")) {
            return Boolean.FALSE;
        }
        try {
            return new BigInteger(token);
        } catch (NumberFormatException e) {
            return token;
        }
    }

    /** {@code (SIZE (1..8))} and the bare {@code SIZE (1..8)} of a SEQUENCE OF, or a plain value range. */
    private void constraint(Node node) {
        boolean bare = peek().equals("SIZE");
        boolean size = bare;
        if (bare) {
            require("SIZE");
            require("(");
        } else {
            require("(");
            size = accept("SIZE");
            if (size) {
                require("(");
            }
        }
        List<Range> ranges = new ArrayList<>();
        do {
            BigInteger low = bound(take());
            ranges.add(accept("..") ? new Range(low, bound(take())) : new Range(low, low));
        } while (accept("|"));
        require(")");
        if (!bare && size) {
            require(")");
        }
        if (size) {
            node.sizes = List.copyOf(ranges);
        } else if (ranges.size() == 1) {
            node.valueRange = ranges.get(0);
        }
    }

    private static BigInteger bound(String token) {
        if (token.equals("MAX") || token.equals("MIN")) {
            return null;
        }
        try {
            return new BigInteger(token);
        } catch (NumberFormatException e) {
            throw new ValidationException(
                    "The extension's ASN.1 module constrains a type with '%s', which is not a number".formatted(token));
        }
    }

    // ---------- resolution ----------

    private ExtensionType resolve(Node node, Node memberContext, Deque<String> inProgress) {
        if (node.kind.equals("reference")) {
            return resolveReference(node, memberContext, inProgress);
        }
        return switch (node.kind) {
            case "scalar" -> new Scalar(node.primitive, node.valueRange, node.sizes, null);
            case "opaque" -> new Opaque(node.reference);
            case "repeated" -> new Repeated(resolve(node.element, null, inProgress), node.set, singleSize(node));
            case "choice" -> new Choice(memberList(node, inProgress));
            case "structure" -> new Structure(memberList(node, inProgress), node.set, singleSize(node));
            default -> throw new IllegalStateException("unreachable kind " + node.kind);
        };
    }

    /**
     * A reference the module does not define cannot be built, so it becomes opaque - except when it is tagged. X.680
     * 31.2.7 makes a tag on an untagged CHOICE explicit even in an IMPLICIT module, so whether the tag wraps or
     * replaces depends on a type that is not here. Guessing would emit different bytes without saying so, which is
     * worse than refusing.
     */
    private ExtensionType resolveReference(Node node, Node memberContext, Deque<String> inProgress) {
        Node target = assignments.get(node.reference);
        boolean tagged = memberContext != null && memberContext.tag != null && memberContext.explicit == null;
        if (target == null && tagged) {
            throw new ValidationException(("The extension's ASN.1 module tags '%s' but does not define it, so "
                    + "its tagging cannot be determined; define it in the module, or tag it EXPLICIT or IMPLICIT")
                    .formatted(node.reference));
        }
        if (target == null || inProgress.contains(node.reference)) {
            return new Opaque(node.reference);
        }
        inProgress.push(node.reference);
        try {
            return resolve(target, memberContext, inProgress);
        } finally {
            inProgress.pop();
        }
    }

    private List<Member> memberList(Node node, Deque<String> inProgress) {
        List<Member> out = new ArrayList<>();
        for (Node member : node.members) {
            ExtensionType type = resolve(member, member, inProgress);
            // A tag on an untagged CHOICE is EXPLICIT whatever the module's default says.
            boolean explicit = member.explicit != null ? member.explicit : type instanceof Choice || !implicitTags;
            out.add(new Member(member.name, type, member.tag, explicit, member.optional, member.defaultValue));
        }
        return out;
    }

    private static Range singleSize(Node node) {
        return node.sizes.size() == 1 ? node.sizes.get(0) : null;
    }
}
