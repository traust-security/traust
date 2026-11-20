class LoginController {
    @GetMapping("/login/done")
    String done(@RequestParam("next") String next) {
        // ruleid: traust-java-open-redirect-taint
        return "redirect:" + next;
    }

    void legacy(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // ruleid: traust-java-open-redirect-taint
        resp.sendRedirect(req.getParameter("return_to"));
        // ok: traust-java-open-redirect-taint
        resp.sendRedirect("/home");
    }

    @GetMapping("/login/safe")
    String selected(@RequestParam("next") String next) {
        // Caller input selects a fixed local route; it is never used as URL text.
        if ("account".equals(next)) {
            // ok: traust-java-open-redirect-taint
            return "redirect:/account";
        }
        // ok: traust-java-open-redirect-taint
        return "redirect:/home";
    }
}
