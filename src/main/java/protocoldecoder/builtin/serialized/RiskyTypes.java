package protocoldecoder.builtin.serialized;

import java.util.List;
import java.util.Locale;

/**
 * Names of classes that are well known as deserialization gadget-chain building blocks. Matching is by name only;
 * it is an indicator for the tester, nothing here generates or alters payloads.
 */
final class RiskyTypes {

    private record Entry(String prefix, String reason) {
    }

    private static final List<Entry> ENTRIES = List.of(
            // Java
            new Entry("org.apache.commons.collections.functors.", "commons-collections functor (gadget chain)"),
            new Entry("org.apache.commons.collections4.functors.", "commons-collections4 functor (gadget chain)"),
            new Entry("org.apache.commons.collections.keyvalue.TiedMapEntry", "commons-collections gadget"),
            new Entry("org.apache.commons.collections4.keyvalue.TiedMapEntry", "commons-collections4 gadget"),
            new Entry("org.apache.commons.collections.map.LazyMap", "commons-collections gadget"),
            new Entry("org.apache.commons.collections4.map.LazyMap", "commons-collections4 gadget"),
            new Entry("org.apache.commons.collections4.comparators.TransformingComparator", "commons-collections4 gadget"),
            new Entry("org.apache.commons.beanutils.BeanComparator", "commons-beanutils gadget"),
            new Entry("org.springframework.beans.factory.ObjectFactory", "Spring gadget"),
            new Entry("org.springframework.core.SerializableTypeWrapper", "Spring gadget"),
            new Entry("org.springframework.aop.framework.JdkDynamicAopProxy", "Spring gadget"),
            new Entry("org.springframework.aop.framework.AdvisedSupport", "Spring gadget"),
            new Entry("org.springframework.transaction.jta.JtaTransactionManager", "Spring JNDI gadget"),
            new Entry("org.springframework.beans.factory.support.AutowireUtils", "Spring gadget"),
            new Entry("org.codehaus.groovy.runtime.ConvertedClosure", "Groovy gadget"),
            new Entry("org.codehaus.groovy.runtime.MethodClosure", "Groovy gadget"),
            new Entry("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", "TemplatesImpl (bytecode loading gadget)"),
            new Entry("org.apache.xalan.xsltc.trax.TemplatesImpl", "TemplatesImpl (bytecode loading gadget)"),
            new Entry("sun.reflect.annotation.AnnotationInvocationHandler", "AnnotationInvocationHandler (gadget chain trigger)"),
            new Entry("javax.management.BadAttributeValueExpException", "BadAttributeValueExpException (gadget chain trigger)"),
            new Entry("java.rmi.server.RemoteObjectInvocationHandler", "RMI/JRMP gadget"),
            new Entry("sun.rmi.server.UnicastRef", "RMI/JRMP gadget"),
            new Entry("sun.rmi.server.ActivationGroupImpl", "RMI gadget"),
            new Entry("java.rmi.registry.Registry", "RMI registry proxy"),
            new Entry("com.sun.rowset.JdbcRowSetImpl", "JdbcRowSetImpl (JNDI gadget)"),
            new Entry("com.mchange.v2.c3p0.", "c3p0 gadget"),
            new Entry("bsh.XThis", "BeanShell gadget"),
            new Entry("bsh.Interpreter", "BeanShell gadget"),
            new Entry("org.mozilla.javascript.NativeJavaObject", "Rhino gadget"),
            new Entry("org.mozilla.javascript.MemberBox", "Rhino gadget"),
            new Entry("clojure.core$comp", "Clojure gadget"),
            new Entry("clojure.main$eval_opt", "Clojure gadget"),
            new Entry("org.python.core.PyFunction", "Jython gadget"),
            new Entry("org.hibernate.tuple.component.AbstractComponentTuplizer", "Hibernate gadget"),
            new Entry("org.hibernate.engine.spi.TypedValue", "Hibernate gadget"),
            new Entry("com.vaadin.data.util.PropertysetItem", "Vaadin gadget"),
            new Entry("org.apache.wicket.util.upload.DiskFileItem", "Wicket gadget"),
            new Entry("org.apache.commons.fileupload.disk.DiskFileItem", "commons-fileupload gadget"),
            new Entry("com.alibaba.fastjson.JSONArray", "fastjson gadget"),
            new Entry("com.fasterxml.jackson.databind.node.POJONode", "Jackson gadget"),
            new Entry("org.jboss.interceptor.", "JBoss interceptor gadget"),
            new Entry("ysoserial.", "ysoserial payload class"),
            // .NET
            new Entry("System.Windows.Data.ObjectDataProvider", "ObjectDataProvider (.NET gadget)"),
            new Entry("System.Data.Services.Internal.ExpandedWrapper", "ExpandedWrapper (.NET gadget)"),
            new Entry("System.Security.Principal.WindowsIdentity", "WindowsIdentity (.NET gadget)"),
            new Entry("System.Security.Claims.ClaimsIdentity", "ClaimsIdentity (.NET gadget)"),
            new Entry("System.Security.Claims.ClaimsPrincipal", "ClaimsPrincipal (.NET gadget)"),
            new Entry("System.Configuration.Install.AssemblyInstaller", "AssemblyInstaller (.NET gadget)"),
            new Entry("System.Windows.Forms.AxHost+State", "AxHost.State (.NET gadget)"),
            new Entry("System.Activities.Presentation.WorkflowDesigner", "WorkflowDesigner (.NET gadget)"),
            new Entry("System.Management.Automation.PSObject", "PSObject (.NET gadget)"),
            new Entry("System.IdentityModel.Tokens.SessionSecurityToken", "SessionSecurityToken (.NET gadget)"),
            new Entry("Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties", "TextFormattingRunProperties (.NET gadget)"),
            new Entry("System.Data.DataSet", "DataSet (.NET gadget)"),
            new Entry("System.Web.Security.RolePrincipal", "RolePrincipal (.NET gadget)"),
            new Entry("System.DelegateSerializationHolder", "delegate serialization (TypeConfuseDelegate)"),
            new Entry("System.Resources.ResXResourceSet", "ResXResourceSet (.NET gadget)"),
            new Entry("System.Web.UI.LosFormatter", "LosFormatter (nested formatter gadget)"),
            new Entry("System.Web.UI.ObjectStateFormatter", "ObjectStateFormatter (nested formatter gadget)"),
            new Entry("System.Runtime.Remoting.", ".NET remoting type"),
            new Entry("System.Diagnostics.Process", "Process (.NET)"),
            // Python
            new Entry("os.system", "command execution"),
            new Entry("os.popen", "command execution"),
            new Entry("os.exec", "command execution"),
            new Entry("os.spawn", "command execution"),
            new Entry("posix.system", "command execution"),
            new Entry("posix.popen", "command execution"),
            new Entry("nt.system", "command execution"),
            new Entry("subprocess.", "command execution"),
            new Entry("commands.", "command execution"),
            new Entry("pty.spawn", "command execution"),
            new Entry("builtins.eval", "code evaluation"),
            new Entry("builtins.exec", "code evaluation"),
            new Entry("builtins.compile", "code evaluation"),
            new Entry("builtins.__import__", "dynamic import"),
            new Entry("builtins.getattr", "attribute access gadget"),
            new Entry("__builtin__.eval", "code evaluation"),
            new Entry("__builtin__.execfile", "code evaluation"),
            new Entry("__builtin__.__import__", "dynamic import"),
            new Entry("__builtin__.getattr", "attribute access gadget"),
            new Entry("runpy.", "code execution"),
            new Entry("webbrowser.open", "process launch"),
            // Ruby
            new Entry("Gem::Requirement", "RubyGems gadget"),
            new Entry("Gem::Installer", "RubyGems gadget"),
            new Entry("Gem::StubSpecification", "RubyGems gadget"),
            new Entry("Gem::Source::SpecificFile", "RubyGems gadget"),
            new Entry("Gem::RequestSet", "RubyGems gadget"),
            new Entry("Gem::Package::TarReader", "RubyGems gadget"),
            new Entry("Net::WriteAdapter", "Net::WriteAdapter gadget"),
            new Entry("Net::BufferedIO", "Net::BufferedIO gadget"),
            new Entry("ERB", "ERB (template evaluation gadget)"),
            new Entry("ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy", "Rails gadget"),
            new Entry("ActiveRecord::Associations::Association", "Rails gadget"),
            new Entry("Rack::Response", "Rack gadget"),
            // PHP (common phpggc chain entry points)
            new Entry("Monolog\\Handler\\", "Monolog (phpggc chain)"),
            new Entry("GuzzleHttp\\Cookie\\FileCookieJar", "Guzzle (phpggc chain)"),
            new Entry("GuzzleHttp\\Psr7\\FnStream", "Guzzle (phpggc chain)"),
            new Entry("Illuminate\\Broadcasting\\PendingBroadcast", "Laravel (phpggc chain)"),
            new Entry("Illuminate\\Foundation\\Testing\\PendingCommand", "Laravel (phpggc chain)"),
            new Entry("Symfony\\Component\\Process\\Process", "Symfony (phpggc chain)"),
            new Entry("Symfony\\Component\\Cache\\Adapter\\", "Symfony (phpggc chain)"),
            new Entry("Swift_ByteStream_", "SwiftMailer (phpggc chain)"),
            new Entry("Doctrine\\", "Doctrine (phpggc chain)"),
            new Entry("Zend\\", "Zend (phpggc chain)"),
            new Entry("Laminas\\", "Laminas (phpggc chain)"),
            new Entry("yii\\", "Yii (phpggc chain)"),
            new Entry("Phar", "Phar")
    );

    private RiskyTypes() {
    }

    /** Reason this type name is a known gadget, or null. */
    static String reason(String name) {
        if (name == null || name.isEmpty()) return null;
        String n = stripAssembly(name);
        for (Entry e : ENTRIES) {
            if (e.prefix.equals("ERB") || e.prefix.equals("Phar")) {
                if (n.equals(e.prefix)) return e.reason;
                continue;
            }
            if (n.startsWith(e.prefix)) return e.reason;
        }
        if (n.toLowerCase(Locale.ROOT).contains("ysoserial")) return "ysoserial payload class";
        // .NET generic arguments: System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Data.ObjectDataProvider, ...
        int gen = n.indexOf("[[");
        if (gen > 0) {
            for (String part : n.substring(gen).split("\\[\\[|\\],\\[|\\]\\]")) {
                String p = part.strip();
                if (!p.isEmpty() && !p.equals(n)) {
                    int comma = p.indexOf(',');
                    String r = reason(comma > 0 ? p.substring(0, comma) : p);
                    if (r != null) return r + " (generic argument)";
                }
            }
        }
        return null;
    }

    /** .NET type names may carry generic arguments and assembly qualification; match on the outer name. */
    private static String stripAssembly(String name) {
        String n = name.strip();
        if (n.startsWith("L") && n.endsWith(";")) n = n.substring(1, n.length() - 1).replace('/', '.');
        return n;
    }
}
