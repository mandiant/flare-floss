import pathlib
import zipfile

import pytest
from floss.language.go.extract import extract_go_strings


@pytest.fixture(scope="module")
def extract_files_64():
    zip_file_path = (
        pathlib.Path(__file__).parent
        / "data"
        / "language"
        / "go"
        / "go-binaries-all-versions"
        / "bin"
        / "versions_64.zip"
    )

    CD = pathlib.Path(__file__).resolve().parent

    abs_zip_path = (CD / zip_file_path).resolve()
    # check if the zip file exists
    assert abs_zip_path.exists(), f"Zip file {zip_file_path} does not exist"

    extracted_files = []

    with zipfile.ZipFile(abs_zip_path, "r") as zip_ref:
        for zip_info in zip_ref.infolist():
            extracted_file_path = (
                CD
                / "data"
                / "language"
                / "go"
                / "go-binaries-all-versions"
                / "bin"
                / "extracted_64"
                / zip_info.filename
            ).resolve()
            print(extracted_file_path)
            extracted_file = zip_ref.extract(zip_info, path=extracted_file_path.parent)
            extracted_files.append(extracted_file)

    print(extracted_files)
    yield

    # Clean up - remove the extracted files after the test finishes
    for extracted_file in extracted_files:
        pathlib.Path(extracted_file).unlink()
    pathlib.Path(extracted_file_path.parent).rmdir()


@pytest.fixture(scope="module")
def extract_files_32():
    zip_file_path = (
        pathlib.Path(__file__).parent
        / "data"
        / "language"
        / "go"
        / "go-binaries-all-versions"
        / "bin"
        / "versions_32.zip"
    )

    CD = pathlib.Path(__file__).resolve().parent

    abs_zip_path = (CD / zip_file_path).resolve()
    # check if the zip file exists
    assert abs_zip_path.exists(), f"Zip file {zip_file_path} does not exist"

    extracted_files = []

    with zipfile.ZipFile(abs_zip_path, "r") as zip_ref:
        for zip_info in zip_ref.infolist():
            extracted_file_path = (
                CD
                / "data"
                / "language"
                / "go"
                / "go-binaries-all-versions"
                / "bin"
                / "extracted_32"
                / zip_info.filename
            ).resolve()
            print(extracted_file_path)
            extracted_file = zip_ref.extract(zip_info, path=extracted_file_path.parent)
            extracted_files.append(extracted_file)

    print(extracted_files)
    yield

    # Clean up - remove the extracted files after the test finishes
    for extracted_file in extracted_files:
        pathlib.Path(extracted_file).unlink()
    pathlib.Path(extracted_file_path.parent).rmdir()


@pytest.mark.parametrize(
    "binary_file",
    [
        ("data/language/go/go-binaries-all-versions/bin/extracted_64/main1.12.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_64/main1.13.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_64/main1.14.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_64/main1.15.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_64/main1.16.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_64/main1.17.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_64/main1.18.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_64/main1.19.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_64/main1.20.exe"),
    ],
)
def test_language_detection_64(binary_file, extract_files_64):
    expected_strings = [
        "Something is wrong with your computer, ",
        "You Cracked it, A Hero is born",
        "Don't Worry, Relax, Chill and Try harder",
        "Enter Password: ",
    ]

    CD = pathlib.Path(__file__).resolve().parent
    abs_path = (CD / binary_file).resolve()

    assert abs_path.exists(), f"File {binary_file} does not exist"

    go_strings = extract_go_strings(abs_path, 6)

    strings = []

    for go_string in go_strings:
        strings.append(go_string.string)

    assert all(elem in strings for elem in expected_strings)


@pytest.mark.parametrize(
    "binary_file",
    [
        ("data/language/go/go-binaries-all-versions/bin/extracted_32/main1.12.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_32/main1.13.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_32/main1.14.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_32/main1.15.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_32/main1.16.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_32/main1.17.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_32/main1.18.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_32/main1.19.exe"),
        ("data/language/go/go-binaries-all-versions/bin/extracted_32/main1.20.exe"),
    ],
)
def test_language_detection_32(binary_file, extract_files_32):
    expected_strings = [
        "Something is wrong with your computer, ",
        "You Cracked it, A Hero is born",
        "Don't Worry, Relax, Chill and Try harder",
        "Enter Password: ",
    ]

    CD = pathlib.Path(__file__).resolve().parent
    abs_path = (CD / binary_file).resolve()

    assert abs_path.exists(), f"File {binary_file} does not exist"

    go_strings = extract_go_strings(abs_path, 6)

    strings = []

    for go_string in go_strings:
        strings.append(go_string.string)

    assert all(elem in strings for elem in expected_strings)
