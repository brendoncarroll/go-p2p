package p2p

type composedSecureSwarm[A Addr] struct {
	Swarm[A]
	Secure[A]
}

type composedAskSwarm[A Addr] struct {
	Swarm[A]
	Asker[A]
}

type composedSecureAskSwarm [A Addr]struct {
	Swarm[A]
	Asker[A]
	Secure[A]
}

func ComposeAskSwarm[A Addr](swarm Swarm[A], ask Asker[A]) AskSwarm[A] {
	return composedAskSwarm[A]{
		Swarm: swarm,
		Asker: ask,
	}
}

func ComposeSecureAskSwarm[A Addr](swarm Swarm[A], ask Asker[A], sec Secure[A]) SecureAskSwarm[A] {
	return composedSecureAskSwarm[A]{
		Swarm:  swarm,
		Asker:  ask,
		Secure: sec,
	}
}

func ComposeSecureSwarm[A Addr](swarm Swarm[A], sec Secure[A]) SecureSwarm[A] {
	return composedSecureSwarm[A]{
		Swarm:  swarm,
		Secure: sec,
	}
}
