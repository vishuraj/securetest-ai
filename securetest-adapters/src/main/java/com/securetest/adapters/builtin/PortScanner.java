package com.securetest.adapters.builtin;

import com.securetest.core.model.Enums.Confidence;
import com.securetest.core.model.Enums.FieldType;
import com.securetest.core.model.Enums.ScanMode;
import com.securetest.core.model.Finding;
import com.securetest.core.model.ModuleCatalog;
import com.securetest.core.model.Severity;
import com.securetest.core.spi.FieldSpec;
import com.securetest.core.spi.PreflightCheck;
import com.securetest.core.spi.ScanContext;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** TCP connect check of an explicit port list on ONE allowlisted host (SRS 5.9). Active scan. */
public class PortScanner implements Scanner {

    public static final String ID = "builtin-port-exposure";

    private record Risk(Severity severity, String service, String advice) { }

    private static final Map<Integer, Risk> RISKY = Map.ofEntries(
            Map.entry(21, new Risk(Severity.MEDIUM, "FTP", "FTP sends credentials in clear text; use SFTP.")),
            Map.entry(23, new Risk(Severity.HIGH, "Telnet", "Telnet is unencrypted; disable it and use SSH.")),
            Map.entry(445, new Risk(Severity.HIGH, "SMB", "Do not expose SMB beyond trusted networks.")),
            Map.entry(1433, new Risk(Severity.MEDIUM, "SQL Server", "Databases should only be reachable from application subnets.")),
            Map.entry(1521, new Risk(Severity.MEDIUM, "Oracle DB", "Databases should only be reachable from application subnets.")),
            Map.entry(2375, new Risk(Severity.CRITICAL, "Docker API (no TLS)", "An unauthenticated Docker API gives root on the host. Close it or use TLS (2376).")),
            Map.entry(3306, new Risk(Severity.MEDIUM, "MySQL", "Databases should only be reachable from application subnets.")),
            Map.entry(3389, new Risk(Severity.HIGH, "RDP", "Expose RDP only via VPN/bastion.")),
            Map.entry(5432, new Risk(Severity.MEDIUM, "PostgreSQL", "Databases should only be reachable from application subnets.")),
            Map.entry(5900, new Risk(Severity.HIGH, "VNC", "Expose VNC only via VPN/bastion.")),
            Map.entry(6379, new Risk(Severity.HIGH, "Redis", "Redis has weak default auth; restrict network access and enable ACLs/TLS.")),
            Map.entry(9200, new Risk(Severity.HIGH, "Elasticsearch", "Restrict network access and enable authentication.")),
            Map.entry(11211, new Risk(Severity.HIGH, "Memcached", "Memcached has no authentication; restrict to localhost/private networks.")),
            Map.entry(27017, new Risk(Severity.HIGH, "MongoDB", "Restrict network access and enable authentication."))
    );

    @Override
    public ScannerDescriptor descriptor() {
        return ScannerDescriptor.builder(ID, ModuleCatalog.NETWORK_SECURITY, "Port exposure check")
                .purpose("Attempts TCP connections to an explicit list of ports on one allowlisted host and reports open services, "
                        + "highlighting databases, remote-admin and unauthenticated services.")
                .access("TCP connect attempts (no payloads) to the allowlisted host only.")
                .mode(ScanMode.ACTIVE).requiresTarget()
                .duration("Seconds (bounded by rate and timeout)")
                .prerequisite("Explicit authorization to scan the host; never run against networks you do not own")
                .field(FieldSpec.required("host", "Host", FieldType.TEXT, "localhost", "Single host name or IP on the allowlist. CIDR ranges are not accepted here."))
                .field(FieldSpec.optional("ports", "Ports", FieldType.LIST, "21,22,23,25,80,443,445,1433,1521,2375,3306,3389,5432,5672,5900,6379,8080,8443,9200,11211,27017",
                        "Comma-separated ports or ranges (e.g. 8000-8100). Max 1024 ports."))
                .field(FieldSpec.number("timeoutMs", "Connect timeout (ms)", 500, 100, 5000, ""))
                .field(FieldSpec.number("rate", "Ports per second", 20, 1, 200, ""))
                .build();
    }

    @Override
    public List<PreflightCheck> preflight(ScanContext ctx) {
        String host = ctx.option("host", "");
        List<PreflightCheck> out = new ArrayList<>();
        out.add(ctx.targets().isAllowedHost(host) ? PreflightCheck.ok("Allowlist", host + " is authorized")
                : PreflightCheck.error("Allowlist", host + " is not on the target allowlist"));
        try {
            out.add(PreflightCheck.ok("Ports", parsePorts(ctx.option("ports", "")).size() + " port(s)"));
        } catch (IllegalArgumentException e) {
            out.add(PreflightCheck.error("Ports", e.getMessage()));
        }
        return out;
    }

    static Set<Integer> parsePorts(String spec) {
        Set<Integer> ports = new LinkedHashSet<>();
        for (String p : spec.split(",")) {
            String t = p.trim();
            if (t.isEmpty()) continue;
            if (t.contains("-")) {
                String[] r = t.split("-");
                int a = Integer.parseInt(r[0].trim());
                int b = Integer.parseInt(r[1].trim());
                for (int i = Math.max(1, a); i <= Math.min(65535, b); i++) ports.add(i);
            } else {
                ports.add(Integer.parseInt(t));
            }
            if (ports.size() > 1024) throw new IllegalArgumentException("At most 1024 ports per scan.");
        }
        return ports;
    }

    @Override
    public void scan(ScanContext ctx) throws Exception {
        String host = ctx.targets().requireAllowedHost(ctx.option("host", ""));
        Set<Integer> ports = parsePorts(ctx.option("ports", "22,80,443"));
        int timeout = ctx.intOption("timeoutMs", 500, 100, 5000);
        long interval = 1000L / ctx.intOption("rate", 20, 1, 200);
        List<Integer> open = new ArrayList<>();
        int i = 0;
        for (int port : ports) {
            ctx.checkCancelled();
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, port), timeout);
                open.add(port);
            } catch (java.io.IOException ignored) {
                // closed / filtered
            }
            Thread.sleep(interval);
            ctx.progress(100 * ++i / ports.size(), "Checked " + i + "/" + ports.size() + " ports");
        }
        ctx.putResult("openPorts", open);
        for (int port : open) {
            Risk r = RISKY.get(port);
            Finding f = Finding.of(ModuleCatalog.NETWORK_SECURITY, ID, "PORT-" + port,
                            r == null ? "Open port " + port + " on " + host : r.service() + " port " + port + " reachable on " + host,
                            r == null ? Severity.INFO : r.severity())
                    .description(r == null ? "TCP port " + port + " accepts connections. Confirm the service is intended to be reachable."
                            : r.service() + " is reachable from the scanning location.")
                    .remediation(r == null ? "Close unused ports with host or network firewall rules." : r.advice())
                    .evidence("TCP connect to " + host + ":" + port + " succeeded").asset(host + ":" + port).category("Network exposure")
                    .confidence(Confidence.HIGH).tags("CIS-NETWORK", "PCI-1.3", "ISO27001-A.8.20");
            ctx.report(f);
        }
    }
}
