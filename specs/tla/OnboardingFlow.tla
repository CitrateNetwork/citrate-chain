------------------------ MODULE OnboardingFlow ------------------------
EXTENDS Naturals, FiniteSets, TLC

\* Models the 13-step GUI onboarding state machine.
\* Source: gui/citrate_gui_v2/src/features/onboarding/
\*
\* The onboarding flow is sequential with one branch point: the user
\* chooses either Privy (social) authentication or traditional (password)
\* authentication. After the auth branch converges at device_binding,
\* the remaining steps are strictly sequential.

CONSTANTS
    MaxRetries      \* Maximum retry attempts for any failable step

ASSUME MaxRetries \in Nat /\ MaxRetries >= 0

VARIABLES
    step,           \* Current onboarding step (see Steps set)
    retries,        \* Retry counter for the current step
    authMethod,     \* Chosen auth method: "none" | "privy" | "traditional"
    visited         \* Set of steps that have been completed

vars == <<step, retries, authMethod, visited>>

\* ---- Step definitions ----

Steps == {
    "launch_check",
    "identity_selection",
    "privy_auth",
    "traditional_auth",
    "device_binding",
    "wallet_provisioning",
    "security_confirmation",
    "environment_selection",
    "node_bootstrap",
    "core_model_readiness",
    "interactive_lesson",
    "hello_world_deploy",
    "session_active"
}

AuthMethods == {"none", "privy", "traditional"}

\* Steps that can fail and be retried
FailableSteps == {
    "privy_auth",
    "traditional_auth",
    "node_bootstrap",
    "core_model_readiness",
    "hello_world_deploy"
}

\* ---- State machine ----

Init ==
    /\ step = "launch_check"
    /\ retries = 0
    /\ authMethod = "none"
    /\ visited = {}

\* launch_check -> identity_selection
LaunchCheckComplete ==
    /\ step = "launch_check"
    /\ step' = "identity_selection"
    /\ visited' = visited \cup {"launch_check"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* identity_selection -> privy_auth (choose Privy)
ChoosePrivy ==
    /\ step = "identity_selection"
    /\ authMethod = "none"
    /\ step' = "privy_auth"
    /\ authMethod' = "privy"
    /\ visited' = visited \cup {"identity_selection"}
    /\ retries' = 0

\* identity_selection -> traditional_auth (choose traditional)
ChooseTraditional ==
    /\ step = "identity_selection"
    /\ authMethod = "none"
    /\ step' = "traditional_auth"
    /\ authMethod' = "traditional"
    /\ visited' = visited \cup {"identity_selection"}
    /\ retries' = 0

\* privy_auth -> device_binding (success)
PrivyAuthSuccess ==
    /\ step = "privy_auth"
    /\ step' = "device_binding"
    /\ visited' = visited \cup {"privy_auth"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* privy_auth retry on failure
PrivyAuthFail ==
    /\ step = "privy_auth"
    /\ retries < MaxRetries
    /\ retries' = retries + 1
    /\ UNCHANGED <<step, authMethod, visited>>

\* traditional_auth -> device_binding (success)
TraditionalAuthSuccess ==
    /\ step = "traditional_auth"
    /\ step' = "device_binding"
    /\ visited' = visited \cup {"traditional_auth"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* traditional_auth retry on failure
TraditionalAuthFail ==
    /\ step = "traditional_auth"
    /\ retries < MaxRetries
    /\ retries' = retries + 1
    /\ UNCHANGED <<step, authMethod, visited>>

\* device_binding -> wallet_provisioning
DeviceBindingComplete ==
    /\ step = "device_binding"
    /\ step' = "wallet_provisioning"
    /\ visited' = visited \cup {"device_binding"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* wallet_provisioning -> security_confirmation
WalletProvisioningComplete ==
    /\ step = "wallet_provisioning"
    /\ step' = "security_confirmation"
    /\ visited' = visited \cup {"wallet_provisioning"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* security_confirmation -> environment_selection
SecurityConfirmationComplete ==
    /\ step = "security_confirmation"
    /\ step' = "environment_selection"
    /\ visited' = visited \cup {"security_confirmation"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* environment_selection -> node_bootstrap
EnvironmentSelectionComplete ==
    /\ step = "environment_selection"
    /\ step' = "node_bootstrap"
    /\ visited' = visited \cup {"environment_selection"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* node_bootstrap -> core_model_readiness (success)
NodeBootstrapSuccess ==
    /\ step = "node_bootstrap"
    /\ step' = "core_model_readiness"
    /\ visited' = visited \cup {"node_bootstrap"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* node_bootstrap retry on failure
NodeBootstrapFail ==
    /\ step = "node_bootstrap"
    /\ retries < MaxRetries
    /\ retries' = retries + 1
    /\ UNCHANGED <<step, authMethod, visited>>

\* core_model_readiness -> interactive_lesson (success)
CoreModelReadinessSuccess ==
    /\ step = "core_model_readiness"
    /\ step' = "interactive_lesson"
    /\ visited' = visited \cup {"core_model_readiness"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* core_model_readiness retry on failure
CoreModelReadinessFail ==
    /\ step = "core_model_readiness"
    /\ retries < MaxRetries
    /\ retries' = retries + 1
    /\ UNCHANGED <<step, authMethod, visited>>

\* interactive_lesson -> hello_world_deploy
InteractiveLessonComplete ==
    /\ step = "interactive_lesson"
    /\ step' = "hello_world_deploy"
    /\ visited' = visited \cup {"interactive_lesson"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* hello_world_deploy -> session_active (success)
HelloWorldDeploySuccess ==
    /\ step = "hello_world_deploy"
    /\ step' = "session_active"
    /\ visited' = visited \cup {"hello_world_deploy"}
    /\ retries' = 0
    /\ UNCHANGED <<authMethod>>

\* hello_world_deploy retry on failure
HelloWorldDeployFail ==
    /\ step = "hello_world_deploy"
    /\ retries < MaxRetries
    /\ retries' = retries + 1
    /\ UNCHANGED <<step, authMethod, visited>>

\* Terminal state: session_active is absorbing
SessionActive ==
    /\ step = "session_active"
    /\ UNCHANGED vars

Next ==
    \/ LaunchCheckComplete
    \/ ChoosePrivy
    \/ ChooseTraditional
    \/ PrivyAuthSuccess
    \/ PrivyAuthFail
    \/ TraditionalAuthSuccess
    \/ TraditionalAuthFail
    \/ DeviceBindingComplete
    \/ WalletProvisioningComplete
    \/ SecurityConfirmationComplete
    \/ EnvironmentSelectionComplete
    \/ NodeBootstrapSuccess
    \/ NodeBootstrapFail
    \/ CoreModelReadinessSuccess
    \/ CoreModelReadinessFail
    \/ InteractiveLessonComplete
    \/ HelloWorldDeploySuccess
    \/ HelloWorldDeployFail
    \/ SessionActive

\* ---- Invariants ----

\* INV-1: TypeOK — all variables in valid domains
TypeOK ==
    /\ step \in Steps
    /\ retries \in 0..MaxRetries
    /\ authMethod \in AuthMethods
    /\ visited \subseteq Steps

\* INV-2: NoSkipSteps — cannot reach session_active without
\*         passing through wallet_provisioning
NoSkipSteps ==
    step = "session_active" => "wallet_provisioning" \in visited

\* INV-3: ModelReadyBeforeLesson — core_model_readiness must be
\*         reached (visited) before interactive_lesson can begin
ModelReadyBeforeLesson ==
    step = "interactive_lesson" => "core_model_readiness" \in visited

\* INV-4: AuthMethodChosen — if past identity_selection, an auth
\*         method must have been chosen
AuthMethodChosen ==
    step \notin {"launch_check", "identity_selection"} =>
        authMethod \in {"privy", "traditional"}

\* INV-5: AuthBranchConsistency — privy_auth visited implies privy
\*         method chosen, and vice versa for traditional
AuthBranchConsistency ==
    /\ ("privy_auth" \in visited => authMethod = "privy")
    /\ ("traditional_auth" \in visited => authMethod = "traditional")

\* INV-6: RetryBounded — retry count never exceeds maximum
RetryBounded ==
    retries <= MaxRetries

\* ---- Specification ----

Spec == Init /\ [][Next]_vars

THEOREM TypeSafe == Spec => []TypeOK
THEOREM NoSkip == Spec => []NoSkipSteps
THEOREM ModelBeforeLesson == Spec => []ModelReadyBeforeLesson
THEOREM AuthChosen == Spec => []AuthMethodChosen
THEOREM AuthConsistent == Spec => []AuthBranchConsistency
THEOREM RetryBound == Spec => []RetryBounded

=============================================================================
