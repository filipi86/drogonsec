package monitor

import (
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// shallowClone fetches only the tip of the given branch (depth=1) into
// targetDir. A shallow clone avoids pulling the full history, which keeps
// the temp-directory small and the scan fast.
//
// Credentials are passed through auth rather than embedded in cloneURL: git
// records the remote URL in the clone's .git/config, so a URL carrying a token
// writes that token to disk in plaintext, where it outlives the clone if the
// process is killed before the temp directory is removed.
func shallowClone(cloneURL, branch, targetDir string, auth transport.AuthMethod) error {
	_, err := gogit.PlainClone(targetDir, false, &gogit.CloneOptions{
		URL:           cloneURL,
		Auth:          auth,
		ReferenceName: plumbing.NewBranchReferenceName(branch),
		SingleBranch:  true,
		Depth:         1,
		NoCheckout:    false,
	})
	return err
}
