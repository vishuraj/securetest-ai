package com.securetest.core.util;

import com.securetest.core.model.Finding;

import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;

/** Safe workspace access: path-traversal protection, excluded directories, size limits, redacted snippets. */
public final class SourceFiles {

    public static final Set<String> EXCLUDED_DIRS = Set.of(".git", ".svn", ".idea", ".vscode", "node_modules", "target",
            "build", "out", "dist", ".gradle", ".mvn", ".securetest", "bin", ".settings", "__pycache__", "vendor");

    private static final Set<String> SENSITIVE_NAMES = Set.of(".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", ".npmrc", ".pypirc");
    private static final long MAX_FILE = 2L * 1024 * 1024;

    private SourceFiles() { }

    /** Resolves a user/finding-supplied relative path, refusing anything outside the root. */
    public static Path resolveInside(Path root, String relative) {
        if (relative == null || relative.isBlank()) throw new IllegalArgumentException("Path required");
        Path normalizedRoot = root.toAbsolutePath().normalize();
        Path p = normalizedRoot.resolve(relative.replace('\\', '/')).normalize();
        if (!p.startsWith(normalizedRoot)) throw new SecurityException("Path escapes the source workspace: " + relative);
        return p;
    }

    /** Files that must never be shown in the code viewer even inside the workspace. */
    public static boolean isSensitive(Path p) {
        String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
        return SENSITIVE_NAMES.contains(name) || name.endsWith(".pem") || name.endsWith(".key") || name.endsWith(".p12")
                || name.endsWith(".jks") || name.endsWith(".pfx") || name.endsWith(".keystore");
    }

    public static List<Path> walk(Path root, Predicate<Path> include, int maxFiles) throws IOException {
        List<Path> out = new ArrayList<>();
        if (root == null || !Files.isDirectory(root)) return out;
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(root) && EXCLUDED_DIRS.contains(dir.getFileName().toString())) return FileVisitResult.SKIP_SUBTREE;
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (attrs.isRegularFile() && attrs.size() <= MAX_FILE && include.test(file)) out.add(file);
                return out.size() >= maxFiles ? FileVisitResult.TERMINATE : FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                return FileVisitResult.CONTINUE;
            }
        });
        return out;
    }

    public static String read(Path file) throws IOException {
        try {
            return Files.readString(file, StandardCharsets.UTF_8);
        } catch (MalformedInputException e) {
            return Files.readString(file, StandardCharsets.ISO_8859_1);
        }
    }

    public static String relative(Path root, Path file) {
        return root.toAbsolutePath().normalize().relativize(file.toAbsolutePath().normalize()).toString().replace('\\', '/');
    }

    /** Builds a redacted snippet with {@code context} lines around [start,end] (1-based). */
    public static List<Finding.CodeLine> snippet(List<String> lines, int start, int end, int context) {
        List<Finding.CodeLine> out = new ArrayList<>();
        int from = Math.max(1, start - context);
        int to = Math.min(lines.size(), end + context);
        for (int i = from; i <= to; i++) {
            String text = Redactor.redact(lines.get(i - 1));
            if (text.length() > 400) text = text.substring(0, 400) + " …";
            out.add(new Finding.CodeLine(i, text, i >= start && i <= end));
        }
        return out;
    }

    /** Attaches location, redacted snippet and file hash to a finding. */
    public static Finding locate(Finding f, Path root, Path file, List<String> lines, int start, int end, String fileHash) {
        f.location(relative(root, file), start, end);
        f.snippet = snippet(lines, start, end, 4);
        f.fileHash = fileHash;
        return f;
    }

    public static String extension(Path p) {
        String n = p.getFileName().toString();
        int i = n.lastIndexOf('.');
        return i < 0 ? "" : n.substring(i + 1).toLowerCase(Locale.ROOT);
    }
}
