use assert_cmd::Command;
use std::fmt::Write;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02X}");
        output
    })
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes_from_stdout(stdout: &[u8]) -> Vec<u8> {
    hex_decode(std::str::from_utf8(stdout.split(|c| *c == b'\n').collect::<Vec<_>>()[0]).unwrap())
}

#[test]
fn full_scenario() -> TestResult {
    // generate key pair
    let mut keygen_cmd = Command::cargo_bin("keygen")?;
    let keygen_output = keygen_cmd.args(["tests/private"]).assert().success();
    let public_key = bytes_from_stdout(&keygen_output.get_output().stdout);

    // encapsulate
    let mut encaps_cmd = Command::cargo_bin("encaps")?;
    let encaps_output = encaps_cmd
        .args([hex_encode(&public_key)])
        .assert()
        .success();
    let (ciphertext, sym_key_1) = {
        // get stdout as string and split it into two parts at \n
        let split_output = encaps_output
            .get_output()
            .stdout
            .split(|c| *c == b'\n')
            .collect::<Vec<_>>();
        (
            hex_decode(std::str::from_utf8(split_output[0]).unwrap()),
            hex_decode(std::str::from_utf8(split_output[1]).unwrap()),
        )
    };

    // decapsulate
    let mut decaps_cmd = Command::cargo_bin("decaps")?;
    let decaps_output = decaps_cmd
        .args(["tests/private", &hex_encode(&ciphertext)])
        .assert()
        .success();
    let sym_key_2 = bytes_from_stdout(&decaps_output.get_output().stdout);

    // verify that encapsulation and decapsulation yielded the same symmetric key
    assert!(sym_key_1 == sym_key_2);
    Ok(())
}
