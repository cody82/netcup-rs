This is a tool that uses the netcup API to update DNS records.
There are already other projects with that functionally, but this one is just a single binary and does not depend on PHP or other runtime environments.

# Compile
You need `cargo` to compile:
```
cargo build --release
```

# Configure
Edit the `netcup-config.dist.json` file according to your needs.

# Run
```
cargo run --release -- --config <path_to_my_config_file>
```
