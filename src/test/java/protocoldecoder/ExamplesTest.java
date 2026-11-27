package protocoldecoder;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.script.SandboxLimits;
import protocoldecoder.script.ScriptDecoder;
import protocoldecoder.script.ScriptDefinition;
import protocoldecoder.script.ScriptSandbox;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ExamplesTest {

    @Test
    void jwtExample() throws Exception {
        String src = Files.readString(Path.of("examples/jwt-bearer.js"));
        try (ScriptSandbox sb = new ScriptSandbox()) {
            ScriptDecoder d = new ScriptDecoder(new ScriptDefinition("jwt", "JWT", "", src), sb, () -> SandboxLimits.DEFAULT);
            assertNull(d.compileError());
            // {"alg":"none"}.{"sub":"alice","exp":2000000000}.
            MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://api.example.com/me")
                    .requestHeader("Authorization", "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsImV4cCI6MjAwMDAwMDAwMH0.").build();
            assertEquals(20, d.match(m).confidence());
            ScriptDecoder.Trace<DecodeResult> t = d.traceDecode(m);
            assertNull(t.error(), t.error());
            assertEquals("JWT none for alice", t.value().summary());
            assertTrue(t.value().root().get("claims").get("exp").value().contains("2033-05-18"));
            assertEquals(2, t.value().warnings().size());
        }
    }
}
