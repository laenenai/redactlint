package testfiles

// canary is a test fixture whose whole purpose is to be searched for in a
// rendering. It must not be reported: an analyzer whose output is mostly
// canaries is one people stop reading. There is no `want` comment here, so
// analysistest fails this package if a diagnostic appears.
type canary struct {
	token string
}
