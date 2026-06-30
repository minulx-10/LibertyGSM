module github.com/minulx-10/LibertyGSM/core-go/tunnel

go 1.26.3

// The clean core (tlsfrag, doh) lives in the parent module; use it locally.
require github.com/minulx-10/LibertyGSM/core-go v0.0.0

replace github.com/minulx-10/LibertyGSM/core-go => ../

require gvisor.dev/gvisor v0.0.0-20260629210000-4c5bd8da3237

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/mobile v0.0.0-20260611195102-4dd8f1dbf5d2 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.46.0 // indirect
)

tool golang.org/x/mobile/cmd/gobind
