// Fixture (signal-synthetic-pid, positive): a JS test signalling a hard-coded pid.
it("stops the recorded browser", () => {
  process.kill(12345, "SIGKILL"); // FLAG
});
