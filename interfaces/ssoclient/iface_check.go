package ssoclient

// These vars exist only to fail compilation if the interfaces drift away
// from the local/remote implementations. They're not used at runtime.
// Keeping them in the parent package avoids a circular import.

// Local implementations live in ssoclient/local; remote in ssoclient/remote.
// To check the interfaces are satisfied without importing those packages
// here (which would be circular), tests in the respective sub-packages do
// the var _ Interface = (*Impl)(nil) check.
