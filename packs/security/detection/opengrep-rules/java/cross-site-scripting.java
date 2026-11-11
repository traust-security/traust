class Greeter extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        // ruleid: traust-java-xss-servlet-writer-taint
        resp.getWriter().write("<h1>Hello " + name + "</h1>");
        // ok: traust-java-xss-servlet-writer-taint
        resp.getWriter().write("<h1>Hello " + Encode.forHtml(name) + "</h1>");
        // ok: traust-java-xss-servlet-writer-taint
        resp.getWriter().write("<h1>Hello</h1>");
    }
}
