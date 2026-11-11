class Previews {
    @GetMapping("/preview")
    String preview(@RequestParam String url) {
        // ruleid: traust-java-ssrf-request-taint
        return restTemplate.getForObject(url, String.class);
    }

    void probe(HttpServletRequest req) throws Exception {
        // ruleid: traust-java-ssrf-request-taint
        HttpURLConnection c = (HttpURLConnection) new URL(req.getParameter("target")).openConnection();
    }

    String fixed() {
        // ok: traust-java-ssrf-request-taint
        return restTemplate.getForObject("https://status.example.com/health", String.class);
    }
}
