package com.czertainly.core.auth.oauth2;

import com.czertainly.core.service.SettingService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.util.List;

@Controller
public class LoginController {

    private SettingService settingService;

    @Autowired
    public void setSettingService(SettingService settingService) {
        this.settingService = settingService;
    }


    @GetMapping("/login")
    public String loginPage(Model model, @RequestParam(value = "redirect", required = false) String redirectUrl,
                            HttpServletRequest request, HttpServletResponse response) throws IOException {
        String originalUrl = request.getHeader("referer");
        if (originalUrl != null) {
            if (redirectUrl != null) {
                originalUrl += redirectUrl.replaceFirst("/", "");
            }
            request.getSession().setAttribute("redirectUrl", originalUrl);
        }
        List<String> oauth2Providers = settingService.listNamesOfOAuth2Providers();

        if (oauth2Providers.isEmpty()) return "no-login-options";

        if (oauth2Providers.size() == 1) response.sendRedirect("oauth2/authorization/" + oauth2Providers.getFirst());

        model.addAttribute("providers", oauth2Providers);
        return "login-options";
    }

    @GetMapping("/oauth2/authorization/{provider}")
    public void loginWithProvider(@PathVariable String provider, HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/" + provider);
    }

}