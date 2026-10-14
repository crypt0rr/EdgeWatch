//go:build linux

package sandbox

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type privateTemporaryExecSetup struct {
	initialization privateTemporaryInit
	stat           unix.Stat_t
	environment    []string
}

// preparePrivateTemporaryExec checks the parent-pinned descriptors and
// handshake packet before the helper applies thread-local restrictions.
func preparePrivateTemporaryExec(request execRequest) (privateTemporaryExecSetup, error) {
	controlType, err := unix.GetsockoptInt(request.controlFD, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || controlType != unix.SOCK_SEQPACKET {
		return privateTemporaryExecSetup{}, errors.New("private temporary control channel is invalid")
	}
	initialization, err := readPrivateTemporaryInit(request.controlFD)
	if err != nil {
		return privateTemporaryExecSetup{}, err
	}
	if err := validatePrivateTemporaryLocation(request.privateRootFD, request.privateLeafFD, initialization); err != nil {
		return privateTemporaryExecSetup{}, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(request.privateLeafFD, &stat); err != nil {
		return privateTemporaryExecSetup{}, errors.New("inspect private temporary leaf failed")
	}
	path := "/tmp/" + initialization.namespaceName + "/" + initialization.name
	environment, err := privateTemporaryExecutionEnvironment(os.Environ(), path)
	if err != nil {
		return privateTemporaryExecSetup{}, errors.New("set private temporary directory failed")
	}
	return privateTemporaryExecSetup{initialization: initialization, stat: stat, environment: environment}, nil
}

// privateTemporaryLandlockRules returns only scanner data descriptors and
// the normal scanner profile. The namespace, leaf, and control descriptors
// remain outside the inherited data-file rules.
func privateTemporaryLandlockRules(request execRequest) ([]landlockPath, []int) {
	inherited := make([]int, request.files)
	for index := range inherited {
		inherited[index] = 3 + index
	}
	return profilePaths(Scanner, os.Getenv), inherited
}

func restrictPrivateTemporary(request execRequest, leafFD int) error {
	if !request.landlock {
		return nil
	}
	paths, inherited := privateTemporaryLandlockRules(request)
	return restrictSelfWithPrivateDirectory(paths, inherited, leafFD)
}

// closePrivateTemporaryControlDescriptors closes every helper-only descriptor
// even if one close reports an error. Scanner data descriptors are untouched.
func closePrivateTemporaryControlDescriptors(descriptors ...int) error {
	var closeErr error
	for _, descriptor := range descriptors {
		if descriptor >= 0 {
			if err := unix.Close(descriptor); err != nil && closeErr == nil {
				closeErr = err
			}
		}
	}
	return closeErr
}
