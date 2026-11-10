package com.securetest.autoconfigure.fleetit;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** A plain service of a microservice system: its own endpoint, Spring Security's defaults and the SecureTest starter. */
@SpringBootApplication
@RestController
public class FleetApp {

    @GetMapping("/hello")
    String hello() {
        return "hi";
    }
}
