module mvdan.cc/garble

// Before the .5 bugfix release, alias tracking via go/types
// was broken; see https://go.dev/issue/70517.
go 1.23.5

require (
	github.com/bluekeyes/go-gitdiff v0.8.1
	github.com/go-quicktest/qt v1.101.0
	github.com/google/go-cmp v0.7.0
	github.com/rogpeppe/go-internal v1.14.1
	golang.org/x/mod v0.24.0
	golang.org/x/tools v0.31.0
	golang.org/x/text v0.24.0
	lukechampine.com/blake3 v1.4.0
)

require (
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
)
