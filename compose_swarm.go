package p2p

type askBidi[A Addr] interface {
	Asker[A]
	AskServer[A]
}

type composedSecureSwarm[A Addr, Pub any] struct {
	Swarm[A]
	Secure[A, Pub]
}

type composedAskSwarm[A Addr] struct {
	Swarm[A]
	askBidi[A]
}

type composedSecureAskSwarm[A Addr, Pub any] struct {
	Swarm[A]
	askBidi[A]
	Secure[A, Pub]
}

func ComposeAskSwarm[A Addr](swarm Swarm[A], ask askBidi[A]) AskSwarm[A] {
	return composedAskSwarm[A]{
		Swarm:   swarm,
		askBidi: ask,
	}
}

func ComposeSecureAskSwarm[A Addr, Pub any](swarm Swarm[A], ask askBidi[A], sec Secure[A, Pub]) SecureAskSwarm[A, Pub] {
	return composedSecureAskSwarm[A, Pub]{
		Swarm:   swarm,
		askBidi: ask,
		Secure:  sec,
	}
}

func ComposeSecureSwarm[A Addr, Pub any](swarm Swarm[A], sec Secure[A, Pub]) SecureSwarm[A, Pub] {
	return composedSecureSwarm[A, Pub]{
		Swarm:  swarm,
		Secure: sec,
	}
}
