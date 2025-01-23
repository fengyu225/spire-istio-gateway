module server

go 1.21.1

require certificate v0.0.0

require (
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

replace certificate => ../certificate
