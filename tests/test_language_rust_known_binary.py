import pathlib
import zipfile

import pytest

from floss.language.rust.extract import extract_rust_strings


@pytest.fixture(scope="module")
def extract_files(request):
    def _extract_files(zip_file_name, extracted_dir_name):
        zip_file_path = (
            pathlib.Path(__file__).parent
            / "data"
            / "language"
            / "rust"
            / "rust-binaries-all-versions"
            / "bin"
            / zip_file_name
        )

        CD = pathlib.Path(__file__).resolve().parent

        abs_zip_path = (CD / zip_file_path).resolve()
        assert abs_zip_path.exists(), f"Zip file {zip_file_path} does not exist"

        extracted_files = []

        with zipfile.ZipFile(abs_zip_path, "r") as zip_ref:
            for zip_info in zip_ref.infolist():
                extracted_file_path = (
                    CD
                    / "data"
                    / "language"
                    / "rust"
                    / "rust-binaries-all-versions"
                    / "bin"
                    / extracted_dir_name
                    / zip_info.filename
                ).resolve()
                extracted_file = zip_ref.extract(zip_info, path=extracted_file_path.parent)
                extracted_files.append(extracted_file)

        yield

        # Clean up - remove the extracted files after the test finishes
        for extracted_file in extracted_files:
            pathlib.Path(extracted_file).unlink()
        pathlib.Path(extracted_file_path.parent).rmdir()

    return _extract_files


@pytest.fixture(scope="module")
def extract_files_64(request, extract_files):
    yield from extract_files("versions_64.zip", "extracted_64")


@pytest.fixture(scope="module")
def extract_files_32(request, extract_files):
    yield from extract_files("versions_32.zip", "extracted_32")


@pytest.mark.parametrize(
    "binary_file",
    [
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_64/rust1.56.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_64/rust1.58.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_64/rust1.60.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_64/rust1.62.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_64/rust1.64.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_64/rust1.66.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_64/rust1.68.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_64/rust1.70.0.exe"),
    ],
)
def test_language_detection_64(binary_file, extract_files_64):
    expected_strings = [
        "the quick brown fox jumps over the lazy dog",
        "Pangram: ",
        "Used characters: ",
        "Alice says: ",
        "Bob says: ",
    ]

    CD = pathlib.Path(__file__).resolve().parent
    abs_path = (CD / binary_file).resolve()

    assert abs_path.exists(), f"File {binary_file} does not exist"

    rust_strings = extract_rust_strings(abs_path, 6)

    strings = []

    for rust_string in rust_strings:
        strings.append(rust_string.string)

    assert all(elem in strings for elem in expected_strings)


@pytest.mark.parametrize(
    "binary_file",
    [
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_32/rust1.56.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_32/rust1.58.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_32/rust1.60.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_32/rust1.62.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_32/rust1.64.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_32/rust1.66.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_32/rust1.68.0.exe"),
        ("data/language/rust/rust-binaries-all-versions/bin/extracted_32/rust1.70.0.exe"),
    ],
)
def test_language_detection_32(binary_file, extract_files_32):
    expected_strings = [
        "the quick brown fox jumps over the lazy dog",
        "Words in reverse",
        "Pangram: ",
        "Used characters: ",
        "Alice says: ",
        "Bob says: ",
    ]

    CD = pathlib.Path(__file__).resolve().parent
    abs_path = (CD / binary_file).resolve()

    assert abs_path.exists(), f"File {binary_file} does not exist"

    rust_strings = extract_rust_strings(abs_path, 6)

    strings = []

    for rust_string in rust_strings:
        strings.append(rust_string.string)

    assert all(elem in strings for elem in expected_strings)
