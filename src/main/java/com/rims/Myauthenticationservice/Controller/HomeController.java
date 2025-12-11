package com.rims.Myauthenticationservice.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/home")
public class HomeController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "Public content - no token required";
    }

    @PreAuthorize("hasRole('VIEWER')")
    @GetMapping("/viewer")
    public String viewerEndpoint() {
        return "Viewer content";
    }

    @PreAuthorize("hasRole('REGULATORY_OFFICER')")
    @GetMapping("/regulatory")
    public String regulatoryEndpoint() {
        return "Regulatory officer content";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Admin content";
    }
}

