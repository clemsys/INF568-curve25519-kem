all: build copy

build:
	cargo build --release

copy:
	cp target/release/{keygen,encaps,decaps} .

clean:
	cargo clean
	rm keygen encaps decaps || true
