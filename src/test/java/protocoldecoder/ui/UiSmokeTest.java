package protocoldecoder.ui;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.script.ScriptDefinition;

import java.awt.Component;
import java.awt.Container;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.concurrent.TimeUnit;
import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;

import static org.junit.jupiter.api.Assertions.*;

/** Builds the real Swing UI headlessly, drives it, and optionally writes PNG snapshots (-PsnapshotDir=...). */
class UiSmokeTest {

    KeyValueStore global = KeyValueStore.inMemory();
    App app = new App(new ConfigStore(global, KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    static MessageContext dxResponse() {
        return MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://shop.example.com/Orders.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("__CALLBACKID=ctl00%24Main%24ASPxGridView1&__CALLBACKPARAM=c0%3AKV%7C2%3B%5B%5D%3BGB%7C20%3B12%7CPAGERONCLICK3%7CPN1%3B")
                .statusCode(200)
                .responseBody("0|/*DX*/({'id':0,'result':{'html':'<table class=\"dxgvTable\"><tr><td>Order 1001</td></tr></table>','stateObject':{'keys':['1001','1002'],'pageIndex':1,'pageCount':12}}})")
                .build();
    }

    void await(MessageDecodePanel p) throws Exception {
        for (int i = 0; i < 200; i++) {
            String[] s = new String[1];
            SwingUtilities.invokeAndWait(() -> s[0] = p.view().current() == null ? null : "ok");
            if (s[0] != null) return;
            TimeUnit.MILLISECONDS.sleep(20);
        }
        fail("decode did not finish");
    }

    @Test
    void decodePanelShowsResultAndPickerOverrides() throws Exception {
        UiEnv env = UiEnv.standalone();
        MessageDecodePanel[] holder = new MessageDecodePanel[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new MessageDecodePanel(app, env));
        MessageDecodePanel p = holder[0];
        MessageContext m = dxResponse();
        SwingUtilities.invokeAndWait(() -> p.setMessage(m));
        await(p);
        SwingUtilities.invokeAndWait(() -> {
            assertTrue(p.view().current().summary().startsWith("Callback result #0"));
            assertTrue(p.statusText().contains("auto-detected"), p.statusText());
            assertEquals(5, p.pickerCount()); // Automatic, DevExpress, New Relic, Blazor, Don't decode
        });
        snapshot(p, "decoded-tab.png", 1100, 520);

        // Choosing "Don't decode" stores a manual override for this message.
        SwingUtilities.invokeAndWait(() -> p.pick(4));
        assertNotNull(app.overrides().get(m.overrideKey()));
        assertFalse(app.engine().resolve(m).hasDecoder());
    }

    @Test
    void blazorRenderBatchSnapshot() throws Exception {
        MessageDecodePanel[] holder = new MessageDecodePanel[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new MessageDecodePanel(app, UiEnv.standalone()));
        byte[] payload = protocoldecoder.BlazorDecoderTest.frames(protocoldecoder.BlazorDecoderTest.l(1, java.util.Map.of(), null,
                "JS.RenderBatch", protocoldecoder.BlazorDecoderTest.l(12, protocoldecoder.BlazorDecoderTest.renderBatch())));
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/_blazor?id=tok123")
                .webSocket("SERVER_TO_CLIENT", payload).build();
        SwingUtilities.invokeAndWait(() -> holder[0].setMessage(m));
        await(holder[0]);
        snapshot(holder[0], "blazor-tab.png", 1100, 560);
    }

    @Test
    void mainTabBuildsWithScripts() throws Exception {
        assertNull(app.saveScript(null, ScriptDefinition.newFromTemplate().id("my-rpc").name("My RPC")));
        MainTab[] t = new MainTab[1];
        SwingUtilities.invokeAndWait(() -> t[0] = new MainTab(app, UiEnv.standalone()));
        assertEquals(4, app.registry().all().size());
        snapshot(t[0], "main-tab.png", 1100, 420);
        // persisted
        assertTrue(global.get("protocoldecoder.scripts").contains("my-rpc"));
    }

    static void snapshot(Component c, String name, int w, int h) throws Exception {
        String dir = System.getProperty("snapshotDir");
        SwingUtilities.invokeAndWait(() -> {
            c.setSize(w, h);
            layout(c);
            layout(c); // second pass: wrapped text knows its width now
            if (dir == null) return;
            BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
            Graphics2D g = img.createGraphics();
            g.setColor(java.awt.Color.WHITE);
            g.fillRect(0, 0, w, h);
            c.printAll(g);
            g.dispose();
            try {
                ImageIO.write(img, "png", new File(dir, name));
            } catch (java.io.IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    static void layout(Component c) {
        if (c instanceof Container ct) {
            ct.doLayout();
            for (Component ch : ct.getComponents()) layout(ch);
        }
    }
}
