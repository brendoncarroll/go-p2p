package p2p

type composedSecureSwarm struct {
	Swarm
	Secure
}

type composedAskSwarm struct {
	Swarm
	Asker
}

type composedSecureAskSwarm struct {
	Swarm
	Asker
	Secure
}

func ComposeAskSwarm(swarm Swarm, ask Asker) AskSwarm {
	return composedAskSwarm{
		Swarm: swarm,
		Asker: ask,
	}
}

func ComposeSecureAskSwarm(swarm Swarm, ask Asker, sec Secure) SecureAskSwarm {
	return composedSecureAskSwarm{
		Swarm:  swarm,
		Asker:  ask,
		Secure: sec,
	}
}

func ComposeSecureSwarm(swarm Swarm, sec Secure) SecureSwarm {
	return composedSecureSwarm{
		Swarm:  swarm,
		Secure: sec,
	}
}
