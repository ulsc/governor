package version

// Version is set at build time via ldflags:
//
//	-ldflags "-X governor/internal/version.Version=v1.0.0"
//
// When built without ldflags it defaults to "dev".
var Version = "dev"
