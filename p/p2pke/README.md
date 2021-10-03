# P2P Key Exchange

P2P Key Exchange is an authenticated key exchange built using the Noise Protocol Framework (NPF).
It requires a message based transport to deliver messages between sessions.

Sessions have a short lifecycle.
They are bounded both by a maximum number of messages (2^31-1) and a maximum age (1 minute).
