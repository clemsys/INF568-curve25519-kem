all: build copy

build:
	cargo build --release

copy:
	cp target/release/keygen .

clean:
	cargo clean
	rm keygen || true
