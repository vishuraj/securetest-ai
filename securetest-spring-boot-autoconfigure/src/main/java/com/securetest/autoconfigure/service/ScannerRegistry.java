package com.securetest.autoconfigure.service;

import com.securetest.autoconfigure.security.ApiException;
import com.securetest.core.spi.Scanner;
import com.securetest.core.spi.ScannerDescriptor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Plugin/adapter registry with capability discovery (SRS 4.4). Any Scanner bean is registered. */
public class ScannerRegistry {

    private final Map<String, Scanner> scanners = new LinkedHashMap<>();

    public ScannerRegistry(List<Scanner> beans) {
        for (Scanner s : beans) {
            ScannerDescriptor d = s.descriptor();
            if (scanners.putIfAbsent(d.getId(), s) != null) {
                throw new IllegalStateException("Duplicate SecureTest scanner id: " + d.getId());
            }
        }
    }

    public Scanner get(String id) {
        Scanner s = scanners.get(id);
        if (s == null) throw ApiException.notFound("Scanner " + id);
        return s;
    }

    public List<ScannerDescriptor> descriptors(String moduleId) {
        return scanners.values().stream().map(Scanner::descriptor)
                .filter(d -> moduleId == null || d.getModuleId().equals(moduleId)).toList();
    }

    public int size() { return scanners.size(); }
}
