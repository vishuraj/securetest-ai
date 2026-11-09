package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * Demo endpoints. Contains DELIBERATE weaknesses so the SecureTest scanners have something to find:
 * weak hashing (MD5), predictable randomness and console logging.
 */
@RestController
@RequestMapping("/api")
public class DemoController {

    private static final List<Map<String, Object>> ITEMS = List.of(
            Map.of("id", 1, "name", "Keyboard", "price", 49.9),
            Map.of("id", 2, "name", "Monitor", "price", 199.0));

    @GetMapping("/items")
    public List<Map<String, Object>> items(@RequestParam(defaultValue = "") String name) {
        System.out.println("Searching items for " + name);
        return ITEMS.stream().filter(i -> i.get("name").toString().toLowerCase().contains(name.toLowerCase())).toList();
    }

    @GetMapping("/fingerprint")
    public String fingerprint(@RequestParam String value) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return HexFormat.of().formatHex(md.digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    @GetMapping("/reset-token")
    public String resetToken() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }
}
