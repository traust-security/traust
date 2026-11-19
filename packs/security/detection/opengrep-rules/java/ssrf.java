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

    @GetMapping("/preview/safe")
    String selected(@RequestParam String service) {
        // Input selects a complete configured URL, never a host or URL fragment.
        // These trusted endpoints must not redirect to attacker-selected destinations.
        if ("status".equals(service)) {
            // ok: traust-java-ssrf-request-taint
            return restTemplate.getForObject("https://status.example.com/health", String.class);
        }
        // ok: traust-java-ssrf-request-taint
        return restTemplate.getForObject("https://docs.example.com/health", String.class);
    }
}
