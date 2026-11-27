package protocoldecoder.builtin.graphql;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class GraphQlDocumentTest {

    @Test
    void formatsNestedSelectionsWithArgumentsAndAliases() {
        GraphQlDocument d = GraphQlDocument.parse("query GetUser($id: ID!, $n: Int = 10) { me: user(id: $id) { id name posts(first: $n) { edges { node { title } } } } viewer { id } }");
        assertEquals("""
                query GetUser($id: ID!, $n: Int = 10) {
                  me: user(id: $id) {
                    id
                    name
                    posts(first: $n) {
                      edges {
                        node {
                          title
                        }
                      }
                    }
                  }
                  viewer {
                    id
                  }
                }""", d.formatted);
        assertTrue(d.warnings.isEmpty(), d.warnings.toString());
        GraphQlDocument.Operation op = d.select(null);
        assertEquals("query", op.type());
        assertEquals("GetUser", op.name());
        assertEquals(List.of("$id: ID!", "$n: Int = 10"), op.variables());
        assertEquals(List.of("me: user", "viewer"), op.rootFields());
        assertFalse(d.introspection);
    }

    @Test
    void formatsFragmentsSpreadsAndDirectives() {
        String src = "query Q @cached(ttl: 60) { node(id: \"1\") { ...UserParts ... on Post @include(if: $p) { title } ... @skip(if: true) { id } } } "
                + "fragment UserParts on User { id avatar(size: [32, 64]) @deprecated }";
        GraphQlDocument d = GraphQlDocument.parse(src);
        assertEquals("""
                query Q @cached(ttl: 60) {
                  node(id: "1") {
                    ...UserParts
                    ... on Post @include(if: $p) {
                      title
                    }
                    ... @skip(if: true) {
                      id
                    }
                  }
                }

                fragment UserParts on User {
                  id
                  avatar(size: [32, 64]) @deprecated
                }""", d.formatted);
        assertEquals(List.of("@cached"), d.operations.get(0).directives());
        assertEquals(1, d.fragments.size());
        assertEquals("UserParts", d.fragments.get(0).name());
        assertEquals("User", d.fragments.get(0).typeCondition());
    }

    @Test
    void keepsCommentsAndStringsIncludingBlockStrings() {
        String src = "# leading comment\nmutation  M { # trailing\n create(input: {text: \"a } { # not a comment\", body: \"\"\"multi\n  line \\\"\"\" { }\"\"\"}) { id } }";
        GraphQlDocument d = GraphQlDocument.parse(src);
        assertTrue(d.warnings.isEmpty(), d.warnings.toString());
        assertTrue(d.formatted.startsWith("# leading comment\nmutation M { # trailing\n  create(input: {"), d.formatted);
        assertTrue(d.formatted.contains("text: \"a } { # not a comment\""), d.formatted);
        assertTrue(d.formatted.contains("\"\"\"multi\n  line \\\"\"\" { }\"\"\""), d.formatted);
        assertEquals("mutation", d.operations.get(0).type());
        assertEquals(List.of("create"), d.operations.get(0).rootFields());
    }

    @Test
    void objectValuesStayInline() {
        GraphQlDocument d = GraphQlDocument.parse("{search(filter:{tags:[\"a\",\"b\"],range:{from:1,to:2}}){total}}");
        assertEquals("""
                {
                  search(filter: { tags: ["a", "b"], range: { from: 1, to: 2 } }) {
                    total
                  }
                }""", d.formatted);
        assertEquals("query", d.operations.get(0).type());
        assertNull(d.operations.get(0).name());
    }

    @Test
    void multipleOperationsAndShorthand() {
        GraphQlDocument d = GraphQlDocument.parse("query A { a } mutation B { b c } subscription C { onEvent { id } }");
        assertEquals(3, d.operations.size());
        assertEquals("B", d.select("B").name());
        assertEquals(List.of("b", "c"), d.select("B").rootFields());
        assertTrue(d.formatted.contains("}\n\nmutation B {"), d.formatted);
    }

    @Test
    void detectsIntrospection() {
        GraphQlDocument d = GraphQlDocument.parse("query IntrospectionQuery { __schema { queryType { name } types { ...FullType } } } fragment FullType on __Type { kind name }");
        assertTrue(d.introspection);
        GraphQlDocument t = GraphQlDocument.parse("{ __type(name: \"User\") { fields { name } } }");
        assertTrue(t.introspection);
        assertFalse(GraphQlDocument.parse("{ user { __typename } }").introspection);
    }

    @Test
    void fallsBackToRawTextOnSyntaxErrors() {
        String src = "query { user(name: \"unterminated) { id } }";
        GraphQlDocument d = GraphQlDocument.parse(src);
        assertFalse(d.lexicallyValid);
        assertEquals(src, d.formatted);
        assertTrue(d.warnings.stream().anyMatch(w -> w.contains("Unterminated string")), d.warnings.toString());

        GraphQlDocument b = GraphQlDocument.parse("query { a { b }");
        assertTrue(b.warnings.stream().anyMatch(w -> w.contains("unclosed")), b.warnings.toString());
        assertNotNull(b.formatted);

        GraphQlDocument c = GraphQlDocument.parse("{ a } } )");
        assertTrue(c.warnings.stream().anyMatch(w -> w.contains("mismatched")), c.warnings.toString());

        GraphQlDocument e = GraphQlDocument.parse("\"\"\"never closed");
        assertTrue(e.warnings.stream().anyMatch(w -> w.contains("Unterminated block string")), e.warnings.toString());

        assertNotNull(GraphQlDocument.parse("").formatted);
        assertNotNull(GraphQlDocument.parse("}}}]]]))) @@@ ... 1.2.3 -x").formatted);
    }

    @Test
    void lexerHandlesNumbersAndEscapes() {
        GraphQlLexer.Result r = GraphQlLexer.tokenize("f(a: -1.5e10, b: 0, c: \"\\\"q\\\"\", d: 12abc)", 1000);
        assertEquals(1, r.errors.size(), r.errors.toString());
        assertTrue(r.tokens.stream().anyMatch(t -> t.kind() == GraphQlLexer.Kind.NUMBER && t.text().equals("-1.5e10")));
        assertTrue(r.tokens.stream().anyMatch(t -> t.kind() == GraphQlLexer.Kind.STRING && t.text().equals("\"\\\"q\\\"\"")));
        GraphQlLexer.Result capped = GraphQlLexer.tokenize("{ a b c d e f }", 3);
        assertTrue(capped.truncated);
    }

    @Test
    void likelyDocumentHeuristic() {
        assertTrue(GraphQlDocument.isLikelyDocument("{ me { id } }"));
        assertTrue(GraphQlDocument.isLikelyDocument("query { me }"));
        assertTrue(GraphQlDocument.isLikelyDocument("query Q($a: Int) { me }"));
        assertTrue(GraphQlDocument.isLikelyDocument("mutation @x { me }"));
        assertTrue(GraphQlDocument.isLikelyDocument("  # c\n fragment F on User { id } query { ...F }"));
        assertTrue(GraphQlDocument.isLikelyDocument("{ ...F }"));
        assertFalse(GraphQlDocument.isLikelyDocument("john smith"));
        assertFalse(GraphQlDocument.isLikelyDocument("select * from users where {x}"));
        assertFalse(GraphQlDocument.isLikelyDocument("query"));
        assertFalse(GraphQlDocument.isLikelyDocument("{\"a\": 1}"));
        assertFalse(GraphQlDocument.isLikelyDocument("{}"));
        assertFalse(GraphQlDocument.isLikelyDocument("query { a ~ b }"));
        assertFalse(GraphQlDocument.isLikelyDocument(null));
        assertFalse(GraphQlDocument.isLikelyDocument("type User { id: ID }"));
    }

    @Test
    void sdlIsReportedAsOtherDefinitions() {
        GraphQlDocument d = GraphQlDocument.parse("type User { id: ID! name: String }");
        assertTrue(d.operations.isEmpty());
        assertEquals(List.of("type User"), d.otherDefinitions);
    }

    @Test
    void largeDocumentIsNotFormatted() {
        String big = "{ a }" + " ".repeat(GraphQlDocument.MAX_FORMAT_CHARS);
        GraphQlDocument d = GraphQlDocument.parse(big);
        assertSame(big, d.formatted);
        assertFalse(d.warnings.isEmpty());
    }
}
