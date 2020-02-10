all: Makefile 
	@cargo test --release --features "test" -- --nocapture --test-threads=1 
