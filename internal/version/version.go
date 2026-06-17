// Package version holds build-time version information injected via -ldflags.
package version

// Version is set at build time via -ldflags "-X .../version.Version=x.y.z"
var Version = "dev"

// BuildTime is set at build time via -ldflags "-X .../version.BuildTime=..."
var BuildTime = "unknown"
