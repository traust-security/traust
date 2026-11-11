package rules

import (
	"fmt"
	"log"
	"os/exec"
)

// stand-in for k8s.io/klog/v2 so the fixture stays stdlib-only; the rules
// match on the call shape `klog.Infof(...)`, not the import.
var klog klogShim

type klogShim struct{}

func (klogShim) Infof(string, ...any) {}
func (klogShim) Info(...any)          {}

func logging(apiToken string, replicas int) {
	// ruleid: traust-go-data-exposure-secret-in-log
	log.Printf("connecting with token %s", apiToken)

	// ruleid: traust-go-data-exposure-secret-in-log
	klog.Infof("auth: %s", apiToken)

	// ruleid: traust-go-data-exposure-secret-in-log
	fmt.Printf("using %v", apiToken)

	// ok: traust-go-data-exposure-secret-in-log
	log.Printf("scaled to %d replicas", replicas)
}

func benignTokenMetadata(tokenURL string, secretName string) {
	// ok: traust-go-data-exposure-secret-in-log
	log.Printf("requesting token from %s", tokenURL)

	// ok: traust-go-data-exposure-secret-in-log
	log.Printf("mounted secret %s", secretName)
}

// credential-adjacent metadata classes from the 2026-07-29 dismissal
// corpus — identity/lifecycle facts about a credential, not its value
func benignCredentialMetadata(tokenExpiresOn string, tokenScope string, credentialFile string, secretErrors []error, tokenReview interface{}) {
	// ok: traust-go-data-exposure-secret-in-log
	log.Printf("token expires at %s", tokenExpiresOn)

	// ok: traust-go-data-exposure-secret-in-log
	log.Printf("token scope %s", tokenScope)

	// ok: traust-go-data-exposure-secret-in-log
	log.Printf("using credential file %s", credentialFile)

	// ok: traust-go-data-exposure-secret-in-log
	log.Printf("secret sync failures: %v", secretErrors)

	// ok: traust-go-data-exposure-secret-in-log
	log.Printf("token review outcome %v", tokenReview)
}

func argv(password string) {
	// ruleid: traust-go-data-exposure-cred-in-argv
	exec.Command("psql", "--password", password)

	// ruleid: traust-go-data-exposure-cred-in-argv
	exec.Command("vault", "login", "-token", password)

	// ok: traust-go-data-exposure-cred-in-argv
	exec.Command("psql", "--host", "db.internal")
}
