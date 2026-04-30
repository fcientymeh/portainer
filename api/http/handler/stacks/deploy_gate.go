package stacks

type deployGate struct {
	start chan struct{}
	abort chan struct{}
}

func newDeployGate() *deployGate {
	return &deployGate{
		start: make(chan struct{}),
		abort: make(chan struct{}),
	}
}

func (gate deployGate) wait() bool {
	select {
	case <-gate.start:
		return true
	case <-gate.abort:
		return false
	}
}

func (gate deployGate) startDeploy() {
	close(gate.start)
}

func (gate deployGate) abortDeploy() {
	close(gate.abort)
}
