package web

import (
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
)

func hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: traust-go-xss-reflected-response-taint
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
	// ruleid: traust-go-xss-reflected-response-taint
	io.WriteString(w, r.FormValue("msg"))
	// ok: traust-go-xss-reflected-response-taint
	fmt.Fprintf(w, "<h1>Hello %s</h1>", html.EscapeString(name))
	// ok: traust-go-xss-reflected-response-taint
	fmt.Fprintf(w, "ok")
}

func preview(w http.ResponseWriter, r *http.Request) {
	// ruleid: traust-go-xss-template-trusted-type
	page.Execute(w, map[string]any{"Snippet": template.HTML(r.FormValue("snippet"))})
	// ok: traust-go-xss-template-trusted-type
	page.Execute(w, map[string]any{"Snippet": template.HTML(policy.Sanitize(r.FormValue("snippet")))})
}

func render(note Note) template.HTML {
	// ok: traust-go-xss-template-trusted-type
	return template.HTML(markdown.Render(note.Body))
}
