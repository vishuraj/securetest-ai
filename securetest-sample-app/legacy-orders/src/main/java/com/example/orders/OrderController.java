package com.example.orders;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotBlank;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {

    @GetMapping("/orders/count")
    public Integer count(HttpServletRequest request) {
        Integer total = new Integer(42);
        return total;
    }

    static class OrderRequest {
        @NotBlank
        String customer;
    }
}
