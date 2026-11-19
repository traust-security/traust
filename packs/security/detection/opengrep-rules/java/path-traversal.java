class Downloads {
    @GetMapping("/manuals/{name}")
    byte[] manual(@PathVariable String name) throws Exception {
        // ruleid: traust-java-path-traversal-request-taint
        return Files.readAllBytes(Paths.get(MANUALS, name));
    }

    @GetMapping("/attachment")
    Resource attachment(@RequestParam("file") String file) {
        // ruleid: traust-java-path-traversal-request-taint
        return new FileSystemResource(file);
    }

    void legacy(HttpServletRequest req) throws Exception {
        // ruleid: traust-java-path-traversal-request-taint
        InputStream in = new FileInputStream(req.getParameter("path"));
    }

    @GetMapping("/safe/{name}")
    byte[] safe(@PathVariable String name) throws Exception {
        // Basename extraction still permits "." and ".."; reject those too.
        // MANUALS must be trusted and contain no attacker-controlled symlinks.
        String leaf = FilenameUtils.getName(name);
        if (leaf.isEmpty() || ".".equals(leaf) || "..".equals(leaf)) {
            throw new IllegalArgumentException("Expected a file name");
        }
        // ok: traust-java-path-traversal-request-taint
        return Files.readAllBytes(Paths.get(MANUALS, leaf));
    }

    byte[] fixed() throws Exception {
        // ok: traust-java-path-traversal-request-taint
        return Files.readAllBytes(Paths.get(MANUALS, "index.html"));
    }
}
