package com.securetest.controlplane.store;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.securetest.controlplane.store.Rows.ts;

/** Remote worker fleet registry. */
@Repository
public class WorkerStore {

    private final JdbcClient jdbc;

    public WorkerStore(JdbcClient jdbc) { this.jdbc = jdbc; }

    public void upsert(String id, String name, String version, String sandbox, String scannersJson) {
        Instant now = Instant.now();
        int n = jdbc.sql("UPDATE worker SET name = :n, version = :v, sandbox = :s, scanners_json = :j, last_seen = :now WHERE id = :id")
                .param("n", name).param("v", version).param("s", sandbox).param("j", scannersJson).param("now", ts(now))
                .param("id", id).update();
        if (n > 0) return;
        try {
            jdbc.sql("""
                    INSERT INTO worker (id, name, version, sandbox, scanners_json, first_seen, last_seen)
                    VALUES (:id, :n, :v, :s, :j, :now, :now)""")
                    .param("id", id).param("n", name).param("v", version).param("s", sandbox).param("j", scannersJson)
                    .param("now", ts(now)).update();
        } catch (DuplicateKeyException race) {
            touch(id);
        }
    }

    public void touch(String id) {
        jdbc.sql("UPDATE worker SET last_seen = :now WHERE id = :id").param("now", ts(Instant.now())).param("id", id).update();
    }

    /** Workers seen since {@code since}, with their scanner catalog JSON. */
    public List<Map<String, Object>> list(Instant since) {
        return jdbc.sql("SELECT * FROM worker WHERE last_seen >= :since ORDER BY id").param("since", ts(since))
                .query((rs, n) -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", rs.getString("id"));
                    m.put("name", rs.getString("name"));
                    m.put("version", rs.getString("version"));
                    m.put("sandbox", rs.getString("sandbox"));
                    m.put("scannersJson", rs.getString("scanners_json"));
                    m.put("firstSeen", Rows.instant(rs, "first_seen"));
                    m.put("lastSeen", Rows.instant(rs, "last_seen"));
                    return m;
                }).list();
    }
}
