package rules

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

// stand-in for github.com/gorilla/mux so the fixture stays stdlib-only;
// the rules match on the call shape `mux.Vars(r)`, not the import.
var mux muxShim

type muxShim struct{}

func (muxShim) Vars(*http.Request) map[string]string { return nil }

func execTaint(w http.ResponseWriter, r *http.Request) {
	// ruleid: traust-go-injection-exec-taint
	exec.Command("kubectl", "get", r.URL.Query().Get("resource"))

	// ruleid: traust-go-injection-exec-taint
	exec.CommandContext(context.TODO(), "oc", r.FormValue("verb"))

	v := mux.Vars(r)
	// ruleid: traust-go-injection-exec-taint
	exec.Command("tool", v["name"])

	// ok: traust-go-injection-exec-taint
	exec.Command("kubectl", "get", "pods")
}

func shellC(dynamic string) {
	// ruleid: traust-go-injection-shell-c
	exec.Command("sh", "-c", dynamic)

	// ruleid: traust-go-injection-shell-c
	exec.CommandContext(context.TODO(), "bash", "-c", "echo "+dynamic)

	// ok: traust-go-injection-shell-c
	exec.Command("sh", "-c", "systemctl restart kubelet")

	// ok: traust-go-injection-shell-c
	exec.Command("ls", "-la", dynamic)
}

func ownedItems(ctx context.Context, db *sql.DB, ownerName string) {
	// ruleid: traust-go-injection-like-wildcard-unescaped
	db.Query("SELECT id FROM item WHERE name LIKE '" + ownerName + "+%'")

	// ruleid: traust-go-injection-like-wildcard-unescaped
	db.QueryContext(ctx, fmt.Sprintf("SELECT id FROM item WHERE name ILIKE '%s%%'", ownerName))

	// ruleid: traust-go-injection-like-wildcard-unescaped
	db.Query("SELECT id FROM item WHERE name LIKE $1", ownerName+"%")

	// ruleid: traust-go-injection-like-wildcard-unescaped
	db.QueryContext(ctx, "SELECT id FROM item WHERE name LIKE $1", "%"+ownerName+"%")

	// ok: traust-go-injection-like-wildcard-unescaped
	db.Query("SELECT id FROM item WHERE name LIKE $1 ESCAPE '\\'", escapeLike(ownerName)+"%")

	// ok: traust-go-injection-like-wildcard-unescaped
	db.Query("SELECT id FROM item WHERE name = $1", ownerName)

	// ok: traust-go-injection-like-wildcard-unescaped
	db.Query("SELECT id FROM item WHERE name LIKE $1", ownerName)

	// ok: traust-go-injection-like-wildcard-unescaped
	db.Query("SELECT id FROM item WHERE owner = '" + ownerName + "'")
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func preview(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("template")
	// ruleid: traust-go-injection-template-parse-taint
	t, _ := template.New("preview").Parse(body)
	// ok: traust-go-injection-template-parse-taint
	fixed, _ := template.New("page").Parse("<p>{{.Name}}</p>")
	_ = t
	_ = fixed
	// Fixed template source with request-controlled data retains template escaping.
	// ok: traust-go-injection-template-parse-taint
	fixed.Execute(w, map[string]string{"Name": r.FormValue("name")})
}

func allowedCommand(w http.ResponseWriter, r *http.Request) {
	switch r.FormValue("resource") {
	case "pods":
		// Only a fixed action is selected; request bytes never become arguments.
		// ok: traust-go-injection-exec-taint
		exec.Command("kubectl", "get", "pods")
	default:
		http.Error(w, "unsupported resource", http.StatusBadRequest)
	}
}
