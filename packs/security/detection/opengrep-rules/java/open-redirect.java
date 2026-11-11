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
}
