"""Build-only protection boundary. Never talks to a board or reads secrets."""
ALLOWED_TARGETS = {
    "buildprog", "size", "checkprogsize", "compiledb", "idedata",
    "envdump", "clean", "fullclean", "menuconfig", "bootloader", "app",
}


def validate_targets(protected, targets):
    """Protected artifacts may only be built; ordinary PIO cannot provision them."""
    if protected:
        denied = set(targets) - ALLOWED_TARGETS
        if denied:
            raise ValueError(
                "Protected profile is BUILD ONLY; device/sign/encrypt targets are blocked. "
                "Provisioning and verified USB updates must be implemented in stages 4/9."
            )


def configure(env, targets):
    profile = env.GetProjectOption("custom_protected_build")
    if str(profile) not in ("0", "1"):
        raise ValueError("Select an explicit test/protected build profile")
    validate_targets(str(profile) == "1", targets)
    # Secrets are deliberately not imported, generated or embedded here.


if "Import" in globals():
    Import("env")
    from SCons.Script import COMMAND_LINE_TARGETS
    try:
        configure(env, COMMAND_LINE_TARGETS)
    except ValueError as exc:
        print(f"Build guard: {exc}")
        env.Exit(1)
