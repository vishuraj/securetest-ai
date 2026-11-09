package com.securetest.autoconfigure;

import org.springframework.http.CacheControl;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Serves the embedded single-page dashboard from the securetest-dashboard-ui jar, like springdoc's swagger-ui. */
public class DashboardWebMvcConfigurer implements WebMvcConfigurer {

    static final String UI_LOCATION = "classpath:/META-INF/securetest-ui/";
    private final String path;

    public DashboardWebMvcConfigurer(String path) {
        this.path = path;
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler(path + "/**")
                .addResourceLocations(UI_LOCATION)
                .setCacheControl(CacheControl.noCache());
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addRedirectViewController(path, path + "/");
        registry.addViewController(path + "/").setViewName("forward:" + path + "/index.html");
    }
}
