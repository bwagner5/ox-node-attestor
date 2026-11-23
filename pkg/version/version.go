// Package version is the build's identity.
package version

// Set by the release build; see .goreleaser.yaml.
var (
	Version = "dev"
	Commit  = ""
)
