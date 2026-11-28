/* Project-authored Apache-2.0. Reads bytes and java.util.jar metadata only. */
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarFile;

class JarReference {
    static String quote(String text) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\\' || c == '"') out.append('\\').append(c);
            else if (c < 32) out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
    static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("one normal JAR filename required");
        Path path = Path.of(args[0]);
        try (JarFile jar = new JarFile(new File(args[0]), false)) {
            System.out.print("{\"file\":" + quote(path.getFileName().toString()) + ",\"sha256\":" + quote(sha(Files.readAllBytes(path))) + ",\"main_attributes\":{");
            Map<String,String> attributes = new TreeMap<>();
            for (var entry : jar.getManifest().getMainAttributes().entrySet()) attributes.put(entry.getKey().toString(), entry.getValue().toString());
            boolean first = true;
            for (var entry : attributes.entrySet()) { if (!first) System.out.print(','); first = false; System.out.print(quote(entry.getKey()) + ':' + quote(entry.getValue())); }
            System.out.print("},\"members\":[");
            var names = new ArrayList<String>();
            var entries = jar.entries(); while (entries.hasMoreElements()) { var entry = entries.nextElement(); if (!entry.isDirectory()) names.add(entry.getName()); }
            Collections.sort(names); first = true;
            for (String name : names) {
                byte[] bytes; try (InputStream stream = jar.getInputStream(jar.getJarEntry(name))) { bytes = stream.readAllBytes(); }
                if (!first) System.out.print(','); first = false;
                System.out.print("{\"path\":" + quote(name) + ",\"size\":" + bytes.length + ",\"sha256\":" + quote(sha(bytes)) + '}');
            }
            System.out.println("]}");
        }
    }
}
