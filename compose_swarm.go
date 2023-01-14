package p2p

type composedSecureSwarm[A Addr, Pub any] struct {
	Swarm[A]
	Secure[A, Pub]
}

type composedAskSwarm[A Addr] struct {
	Swarm[A]
	Asker[A]
}

type composedSecureAskSwarm[A Addr, Pub any] struct {
	Swarm[A]
	Asker[A]
	Secure[A, Pub]
}

func ComposeAskSwarm[A Addr](swarm Swarm[A], ask Asker[A]) AskSwarm[A] {
	return composedAskSwarm[A]{
		Swarm: swarm,
		Asker: ask,
	}
}

func ComposeSecureAskSwarm[A Addr, Pub any](swarm Swarm[A], ask Asker[A], sec Secure[A, Pub]) SecureAskSwarm[A, Pub] {
	return composedSecureAskSwarm[A, Pub]{
		Swarm:  swarm,
		Asker:  ask,
		Secure: sec,
	}
}

func ComposeSecureSwarm[A Addr, Pub any](swarm Swarm[A], sec Secure[A, Pub]) SecureSwarm[A, Pub] {
	return composedSecureSwarm[A, Pub]{
		Swarm:  swarm,
		Secure: sec,
	}
}
