package compat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** A minimal application: its own endpoint, Spring Security's defaults, and the SecureTest starter. Nothing else. */
@SpringBootApplication
@RestController
public class CompatApp {

    @GetMapping("/hello")
    String hello() {
        return "hi";
    }

    public static void main(String[] args) {
        SpringApplication.run(CompatApp.class, args);
    }
}
