# Agent runtime audit notes

The runtime bootstrap installs compatibility fixes before `cli` imports the agent. This keeps provider setup ahead of runtime initialization, fixes the missing mission mode helper lookup, and corrects proxy routing so traffic capture uses the mitmproxy listener when the Burp + mitmproxy stack is active.

The autonomous loop still remains state/iteration driven; a later refactor should move it toward an event-driven THINK -> TOOL -> OBSERVE -> DECIDE state machine with an explicit WAITING_FOR_USER state.
